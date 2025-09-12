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
	"strings"
)

var setPostfixConfigLocker = gmutex.New()

func (c *ControllerV1) SetPostfixConfig(ctx context.Context, req *v1.SetPostfixConfigReq) (res *v1.SetPostfixConfigRes, err error) {
	res = &v1.SetPostfixConfigRes{}

	if req.Key == "" || req.Value == "" {
		res.SetError(gerror.New(public.LangCtx(ctx, "key and value required")))
		return res, nil
	}

	// Allowable configuration for modification
	allowedKeys := map[string]struct{}{
		"bounce_queue_lifetime":  {},
		"maximal_backoff_time":   {},
		"maximal_queue_lifetime": {},
		"minimal_backoff_time":   {},
		"queue_run_delay":        {},
		"trigger_timeout":        {},
	}

	if _, ok := allowedKeys[req.Key]; !ok {
		res.SetError(gerror.Newf(public.LangCtx(ctx, "config key not allowed to modify: {}", req.Key)))
		return res, nil
	}
	setPostfixConfigLocker.Lock()
	defer setPostfixConfigLocker.Unlock()

	postfixCfgPath := v1.ServiceType_Postfix

	data, err := ioutil.ReadFile(postfixCfgPath)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "open main.cf failed: %v", err.Error())))
		return res, nil
	}

	//// Backup
	//backupPath := fmt.Sprintf("%s.bak.%s", postfixCfgPath, time.Now().Format("20060102150405"))
	//if err := ioutil.WriteFile(backupPath, data, 0644); err != nil {
	//	res.SetError(gerror.New(public.LangCtx(ctx, "backup main.cf failed: %v", err.Error())))
	//	return res, nil
	//}

	//  Process line by line
	lines := strings.Split(string(data), "\n")
	found := false
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
		if key == req.Key {
			lines[i] = req.Key + " = " + req.Value
			found = true
			break // Found and replaced, no need to continue loop
		}
	}
	if !found {

		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines = append(lines, "")
		}
		lines = append(lines, req.Key+" = "+req.Value)
	}

	err = ioutil.WriteFile(postfixCfgPath, []byte(strings.Join(lines, "\n")), 0644)
	if err != nil {
		// Attempt to restore from backup
		_ = ioutil.WriteFile(postfixCfgPath, data, 0644)
		res.SetError(gerror.New(public.LangCtx(ctx, "write main.cf failed: %v", err.Error())))
		return res, nil
	}

	//  reload postfix
	dk, err := docker.NewDockerAPI()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "failed to create Docker API instance: %v", err.Error())))
		return res, nil
	}
	defer dk.Close()

	// Restart the Postfix container to apply the changes
	result, err := dk.ExecCommandByName(ctx, consts.SERVICES.Postfix, []string{"postfix", "reload"}, "root")
	if err != nil || result == nil || result.ExitCode != 0 {
		g.Log().Error(ctx, "Failed to reload postfix:", err, result)
		res.SetError(gerror.New(public.LangCtx(ctx, "set config success but reload failed, please check service status")))
		return res, nil
	}
	// Operation Log
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Settings,
		Log:  "Set postfix config [" + req.Key + "] = [" + req.Value + "] successfully",
	})

	res.SetSuccess(public.LangCtx(ctx, "set postfix config success"))
	return res, nil
}
