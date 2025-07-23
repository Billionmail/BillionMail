package domains

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/public"
	"context"

	"billionmail-core/api/domains/v1"
)

func (c *ControllerV1) FreshDNSRecords(ctx context.Context, req *v1.FreshDNSRecordsReq) (res *v1.FreshDNSRecordsRes, err error) {
	res = &v1.FreshDNSRecordsRes{}

	domains.FreshRecords(ctx, req.Domain)

	res.Data = domains.GetRecordsInCache(req.Domain)

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Domain,
		Log:  "Fresh DNS records for domain :" + req.Domain + " successfully",
		Data: res.Data,
	})

	res.SetSuccess(public.LangCtx(ctx, "Success"))
	return
}
