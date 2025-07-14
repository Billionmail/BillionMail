package mail_services

import (
	"billionmail-core/api/mail_services/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/mail_service"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/frame/g"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"
)

func (c *ControllerV1) AddBcc(ctx context.Context, req *v1.AddBccReq) (res *v1.AddBccRes, err error) {
	res = &v1.AddBccRes{}

	count, err := g.DB().Model("bm_bcc").
		Where("type", req.Type).
		Where("address", req.Address).
		Where("goto", req.Goto).
		Count()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "check rule failed: {}", err.Error())))
		return res, nil
	}
	if count > 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "rule already exists")))
		return res, nil
	}

	if req.Domain == "" {
		req.Domain = mail_service.ExtractDomain(req.Address)
	}

	now := time.Now().Unix()
	insertdata := g.Map{
		"type":        req.Type,
		"address":     req.Address,
		"goto":        req.Goto,
		"domain":      req.Domain,
		"create_time": now,
		"update_time": now,
		"active":      req.Active,
	}
	_, err = g.DB().Model("bm_bcc").Insert(insertdata)

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "add bcc rule failed: {}", err.Error())))
		return res, nil
	}

	// sync config immediately to take effect
	if err := mail_service.SyncBccToPostfix(ctx); err != nil {
		g.Log().Error(ctx, "sync bcc config failed: {}", err)
		res.SetError(gerror.New(public.LangCtx(ctx, "add success but sync config failed: {}", err.Error())))
		return res, nil
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.BCC,
		Log:  "Add bcc rule :" + req.Address + " successfully",
		Data: insertdata,
	})

	// set return data
	res.SetSuccess(public.LangCtx(ctx, "add bcc rule success"))
	return res, nil
}
