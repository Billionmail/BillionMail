package settings

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/rbac"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/settings/v1"
)

func (c *ControllerV1) RegenerateAPIToken(ctx context.Context, req *v1.RegenerateAPITokenReq) (res *v1.RegenerateAPITokenRes, err error) {
	res = &v1.RegenerateAPITokenRes{}
	// Get current admin user info from JWT token
	claims, err := rbac.JWT().ParseTokenByRequest(g.RequestFromCtx(ctx))
	g.Log().Error(ctx, "RegenerateAPIToken claims: ", claims)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get current user information: {}", err)))
		return res, nil
	}

	// Generate new API token
	newAPIToken, _, err := rbac.JWT().GenerateApiToken(claims.AccountId, claims.Username, []string{"admin"})
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to generate new API token: {}", err)))
		return res, nil
	}

	// Save new API token to database
	err = public.OptionsMgrInstance.SetOption(ctx, "API_TOKEN", newAPIToken)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to save new API token: {}", err)))
		return res, nil
	}

	// Log the operation
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Settings,
		Log:  "Regenerated API token",
		Data: map[string]interface{}{
			"user":    claims.Username,
			"user_id": claims.AccountId,
		},
	})

	res.Data.APIToken = newAPIToken
	res.SetSuccess(public.LangCtx(ctx, "API token regenerated successfully"))
	return res, nil
}
