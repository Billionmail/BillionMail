package mail_services

import (
	"billionmail-core/api/mail_services/v1"
	"billionmail-core/internal/consts"
	docker "billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gmutex"
	"io/ioutil"
	"reflect"
	"strings"
)

var setAllPostfixConfigLocker = gmutex.New()

func (c *ControllerV1) SetAllPostfixConfig(ctx context.Context, req *v1.SetAllPostfixConfigReq) (res *v1.SetAllPostfixConfigRes, err error) {
	res = &v1.SetAllPostfixConfigRes{}

	fieldToKey := map[string]string{
		"BounceQueueLifetime":  "bounce_queue_lifetime",
		"MaximalBackoffTime":   "maximal_backoff_time",
		"MaximalQueueLifetime": "maximal_queue_lifetime",
		"MinimalBackoffTime":   "minimal_backoff_time",
		"QueueRunDelay":        "queue_run_delay",
		"TriggerTimeout":       "trigger_timeout",
	}

	updated := make([]string, 0)
	skipped := make([]string, 0)

	validConfigs := make(map[string]string)

	v := reflect.ValueOf(req).Elem()
	for field, key := range fieldToKey {
		val := v.FieldByName(field).String()
		if strings.TrimSpace(val) == "" {
			skipped = append(skipped, key)
			continue
		}
		validConfigs[key] = strings.TrimSpace(val)
	}

	if len(validConfigs) == 0 {

		res.SetSuccess(public.LangCtx(ctx, "No valid configurations to update"))
		return res, nil
	}

	setAllPostfixConfigLocker.Lock()
	defer setAllPostfixConfigLocker.Unlock()

	postfixCfgPath := v1.ServiceType_Postfix

	data, err := ioutil.ReadFile(postfixCfgPath)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "open main.cf failed: %v", err.Error())))
		return res, nil
	}

	lines := strings.Split(string(data), "\n")
	existingKeys := make(map[string]int) // key -> line index

	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		parts := strings.SplitN(trim, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		existingKeys[key] = i
	}

	for key, value := range validConfigs {
		if lineIndex, exists := existingKeys[key]; exists {
			lines[lineIndex] = key + " = " + value
		} else {
			if len(lines) > 0 && lines[len(lines)-1] != "" {
				lines = append(lines, "")
			}
			lines = append(lines, key+" = "+value)
		}
		updated = append(updated, key)
	}

	err = ioutil.WriteFile(postfixCfgPath, []byte(strings.Join(lines, "\n")), 0644)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "write main.cf failed: %v", err.Error())))
		return res, nil
	}

	dk, err := docker.NewDockerAPI()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "failed to create Docker API instance: %v", err.Error())))
		return res, nil
	}
	defer dk.Close()

	result, err := dk.ExecCommandByName(ctx, consts.SERVICES.Postfix, []string{"postfix", "reload"}, "root")
	if err != nil || result == nil || result.ExitCode != 0 {
		g.Log().Error(ctx, "Failed to reload postfix:", err, result)
		res.SetError(gerror.New(public.LangCtx(ctx, "set config success but reload failed, please check service status")))
		return res, nil
	}

	configLog := make([]string, 0)
	for key, value := range validConfigs {
		configLog = append(configLog, key+"="+value)
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Settings,
		Log:  "Set postfix configs [" + strings.Join(configLog, ", ") + "] successfully",
	})

	res.SetSuccess(public.LangCtx(ctx, "set postfix configs success"))
	return res, nil
}
