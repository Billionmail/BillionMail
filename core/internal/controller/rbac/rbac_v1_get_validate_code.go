package rbac

import (
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/rbac"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/rbac/v1"
)

func (c *ControllerV1) GetValidateCode(ctx context.Context, req *v1.GetValidateCodeReq) (res *v1.GetValidateCodeRes, err error) {
	res = &v1.GetValidateCodeRes{}

	clientIp := g.RequestFromCtx(ctx).GetClientIp()

	cacheKey := fmt.Sprintf("USER_LOGIN_RETRIES:%s", clientIp)

	res.Data.LoginRetries, res.Data.MustValidateCode = public.GetCache(cacheKey).(int)
	res.Data.MaxLoginRetries = 5
	res.Data.ValidateCodeId, res.Data.ValidateCodeBase64, err = rbac.GetCaptcha()

	if err != nil {
		err = fmt.Errorf("failed to get validate code: %w", err)
		return
	}

	res.SetSuccess(public.LangCtx(ctx, "Success"))

	return
}
