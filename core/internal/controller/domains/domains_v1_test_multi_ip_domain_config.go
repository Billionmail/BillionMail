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

	ok, validateErr := multi_ip_domain.MultiIPDomainServiceInstance.ValidateDNSRecords(ctx, req.Domain, req.OutboundIP)
	if !ok {
		res.SetError(gerror.New(public.LangCtx(ctx, "Test configuration failed: {}", validateErr.Error())))
		return res, nil
	}

	msg := "Configuration test passed successfully"
	if validateErr != nil {
		msg = "Configuration test passed with warnings: " + validateErr.Error()
	}
	res.SetSuccess(public.LangCtx(ctx, msg))

	logDetail := "Success"
	if validateErr != nil {
		logDetail = "Warning: " + validateErr.Error()
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Domain,
		Log:  "Test domain " + req.Domain + " -> " + req.OutboundIP + " (" + logDetail + ")",
		Data: req,
	})

	return res, nil
}
