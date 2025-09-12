package domains

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/multi_ip_domain"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/domains/v1"
)

func (c *ControllerV1) TestMultiIPDomainConfig(ctx context.Context, req *v1.TestMultiIPDomainConfigReq) (res *v1.TestMultiIPDomainConfigRes, err error) {
	res = &v1.TestMultiIPDomainConfigRes{}

	ok, err := multi_ip_domain.MultiIPDomainServiceInstance.ValidateDNSRecords(ctx, req.Domain, req.OutboundIP)
	if !ok {
		res.SetError(gerror.New(public.LangCtx(ctx, "Test configuration failed: {}", err)))
		return res, nil
	}

	res.SetSuccess(public.LangCtx(ctx, "Configuration test passed: {} ", err))

	// 记录操作日志
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Domain,
		Log:  "Test the outboundIP of the domain: " + req.Domain + " -> " + req.OutboundIP + " (" + err.Error() + ")",
		Data: req,
	})

	return res, nil
}
