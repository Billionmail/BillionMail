package domains

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/multi_ip_domain"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/domains/v1"
)

func (c *ControllerV1) ApplyMultiIPDomainConfig(ctx context.Context, req *v1.ApplyMultiIPDomainConfigReq) (res *v1.ApplyMultiIPDomainConfigRes, err error) {
	res = &v1.ApplyMultiIPDomainConfigRes{}

	appliedConfigs, failedConfigs, warnings, err := multi_ip_domain.MultiIPDomainServiceInstance.ApplyConfigs(ctx)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to apply configuration: {}", err.Error())))
		return res, nil
	}

	logMessage := "Applied multi-IP domain configuration"
	if len(failedConfigs) > 0 {
		logMessage += " (partially failed)"
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Domain,
		Log:  logMessage,
		Data: map[string]interface{}{
			"applied":  appliedConfigs,
			"failed":   failedConfigs,
			"warnings": warnings,
		},
	})

	if len(failedConfigs) > 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to apply some configurations, please check the logs")))
		return res, nil
	}
	HostWorkDir := public.HostWorkDir
	projectPath := public.AbsPath("../")
	if HostWorkDir == "" {
		HostWorkDir = projectPath
	}

	res.Data.Command = fmt.Sprintf("cd %s && bash bm.sh multi_ip", HostWorkDir)
	res.Data.FixCommand = fmt.Sprintf("cd %s && bash bm.sh fix_multi_ip ", HostWorkDir)

	res.SetSuccess(public.LangCtx(ctx, "Configuration applied successfully"))
	return res, nil
}
