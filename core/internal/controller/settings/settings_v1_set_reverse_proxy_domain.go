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
	// Add defer to catch panics
	defer func() {
		if r := recover(); r != nil {
			res = &v1.SetReverseProxyDomainRes{}
			res.SetError(gerror.New(public.LangCtx(ctx, "Internal error occurred while testing reverse proxy domain")))
		}
	}()

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

	if respData == nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Reverse proxy domain test failed: received empty response")))
		return res, nil
	}

	// Check code==0 in response
	code, ok := respData["code"].(float64)
	if !ok {
		res.SetError(gerror.New(public.LangCtx(ctx, "Reverse proxy domain test failed: invalid response format, missing code field")))
		return res, nil
	}

	if int(code) != 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "Reverse proxy domain test failed: response code is {}, expected 0", int(code))))
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
