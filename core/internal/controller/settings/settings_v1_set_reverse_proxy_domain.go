package settings

import (
	"billionmail-core/internal/consts"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/settings/v1"
	"billionmail-core/internal/service/public"
	"fmt"
)

func (c *ControllerV1) SetReverseProxyDomain(ctx context.Context, req *v1.SetReverseProxyDomainReq) (res *v1.SetReverseProxyDomainRes, err error) {
	res = &v1.SetReverseProxyDomainRes{}

	domain := req.Domain

	// Test connectivity to https://<domain>/api/languages/get
	testUrl := fmt.Sprintf("%s/api/languages/get", domain)
	var respData map[string]interface{}
	err = public.HttpGetJson(testUrl, 5, &respData)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to connect to reverse proxy domain: {}", err.Error())))
		return res, nil
	}

	// Check code==0 in response
	code, ok := respData["code"].(float64)
	if !ok || int(code) != 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "Reverse proxy domain test failed, unexpected response: {}", err.Error())))
		return res, nil
	}

	// Save to bm_options
	err = public.OptionsMgrInstance.SetOption(ctx, "reverse_proxy_domain", domain)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to save reverse proxy domain: {}", err.Error())))
		return res, nil
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Settings,
		Log:  "Reverse proxy domain set successfully :[" + domain + "]",
	})

	res.SetSuccess(public.LangCtx(ctx, "Reverse proxy domain set successfully"))
	return res, nil
}
