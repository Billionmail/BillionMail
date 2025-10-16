package settings

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/settings/v1"
)

func (c *ControllerV1) DeleteReverseProxyDomain(ctx context.Context, req *v1.DeleteReverseProxyDomainReq) (res *v1.DeleteReverseProxyDomainRes, err error) {
	res = &v1.DeleteReverseProxyDomainRes{}

	// Save to bm_options
	err = public.OptionsMgrInstance.SetOption(ctx, "reverse_proxy_domain", "")
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete the reverse proxy domain name: {}", err.Error())))
		return res, nil
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Settings,
		Log:  "The reverse proxy domain configuration has been successfully deleted.",
	})

	res.SetSuccess(public.LangCtx(ctx, "The reverse proxy domain configuration has been successfully deleted."))
	return res, nil
}
