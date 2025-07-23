package settings

import (
	"billionmail-core/internal/service/domains"
	"context"

	"billionmail-core/api/settings/v1"
	"billionmail-core/internal/service/public"
)

func (c *ControllerV1) GetReverseProxyDomain(ctx context.Context, req *v1.GetReverseProxyDomainReq) (res *v1.GetReverseProxyDomainRes, err error) {
	res = &v1.GetReverseProxyDomainRes{}

	var reverseProxyDomain string
	err = public.OptionsMgrInstance.GetOption(ctx, "reverse_proxy_domain", &reverseProxyDomain)
	if err != nil {
		reverseProxyDomain = ""
	}

	currentUrl := domains.GetBaseURL()

	res.SetSuccess(public.LangCtx(ctx, "Success"))
	res.Data = map[string]interface{}{
		"current_url":          currentUrl,
		"reverse_proxy_domain": reverseProxyDomain,
	}
	return res, nil
}
