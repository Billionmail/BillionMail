package mail_services

import (
	"billionmail-core/internal/service/public"
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/mail_services/v1"
)

func (c *ControllerV1) GetPostfixConfig(ctx context.Context, req *v1.GetPostfixConfigReq) (res *v1.GetPostfixConfigRes, err error) {
	res = &v1.GetPostfixConfigRes{}
	params := []string{"bounce_queue_lifetime", "maximal_queue_lifetime", "minimal_backoff_time", "maximal_backoff_time", "queue_run_delay", "trigger_timeout"}
	defaultConfig := map[string]string{
		"bounce_queue_lifetime":  "5d",
		"maximal_backoff_time":   "4000s",
		"maximal_queue_lifetime": "5d",
		"minimal_backoff_time":   "300s",
		"queue_run_delay":        "300s",
		"trigger_timeout":        "10s",
	}
	config := make(map[string]string)
	mainCfPath := v1.ServiceType_Postfix
	file, err := os.Open(mainCfPath)
	if err != nil {
		g.Log().Debug(ctx, "Failed to open main.cf, use default values:", err)
		for _, key := range params {
			config[key] = defaultConfig[key]
		}
		res.Data = config
		res.SetSuccess(public.LangCtx(ctx, "Success (default values used)"))
		return res, nil
	}
	defer file.Close()
	kv := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			kv[k] = v
		}
	}
	for _, key := range params {
		if val, ok := kv[key]; ok {
			config[key] = val
		} else {
			config[key] = defaultConfig[key]
		}
	}
	res.Data = config
	res.SetSuccess(public.LangCtx(ctx, "Success"))
	return res, nil
}
