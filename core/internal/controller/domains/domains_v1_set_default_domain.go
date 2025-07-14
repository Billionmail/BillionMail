package domains

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/frame/g"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/domains/v1"
)

func (c *ControllerV1) SetDefaultDomain(ctx context.Context, req *v1.SetDefaultDomainReq) (res *v1.SetDefaultDomainRes, err error) {
	res = &v1.SetDefaultDomainRes{}

	// 1. Validate if the domain exists and is active
	var count int
	count, err = g.DB().Model("domain").
		Where("domain", req.Domain).
		Where("active", 1).
		Count()

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "check domain failed: {}", err.Error())))
		return res, nil
	}

	if count == 0 {
		res.SetError(gerror.NewCode(gcode.CodeNotFound, "Domain does not exist or is not activated"))
		return res, nil
	}

	// 2. Write to bm_options
	_, err = g.DB().Model("bm_options").
		Data(g.Map{
			"name":  "default_sender_domain",
			"value": req.Domain,
		}).
		OnConflict("name").
		Save()

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to set default sender domain: {}", err.Error())))
		return
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Domain,
		Log:  "Set default sender domain :" + req.Domain + " successfully",
	})

	res.SetSuccess(public.LangCtx(ctx, "Default sender domain set successfully"))
	return
}
