package mail_services

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/mail_service"
	"context"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"time"

	"billionmail-core/api/mail_services/v1"
	"billionmail-core/internal/service/public"

	"github.com/gogf/gf/v2/errors/gerror"
)

func (c *ControllerV1) EditBcc(ctx context.Context, req *v1.EditBccReq) (res *v1.EditBccRes, err error) {
	res = &v1.EditBccRes{}

	err = g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {

		info, err := tx.Model("bm_bcc").Where("id", req.ID).One()
		if err != nil {
			return gerror.New(public.LangCtx(ctx, "check record failed: {}", err.Error()))
		}
		if info.IsEmpty() {
			return gerror.New(public.LangCtx(ctx, "record not found"))
		}

		// prepare update data
		updateData := g.Map{
			"update_time": time.Now().Unix(),
			"active":      req.Active,
		}

		// check if it is full edit mode
		isFullEdit := req.Type != "" && req.Address != "" && req.Goto != ""

		// if it is full edit mode, update all fields
		if isFullEdit {

			domainValue := req.Domain
			if domainValue == "" {
				domainValue = mail_service.ExtractDomain(req.Address)
			}

			updateData["type"] = req.Type
			updateData["address"] = req.Address
			updateData["goto"] = req.Goto
			updateData["domain"] = domainValue
		}

		_, err = tx.Model("bm_bcc").
			Where("id", req.ID).
			Update(updateData)
		if err != nil {
			return gerror.New(public.LangCtx(ctx, "update record failed: {}", err.Error()))
		}

		return nil
	})

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "update record failed: {}", err.Error())))
		return res, nil
	}

	// sync config immediately to take effect
	if err := mail_service.SyncBccToPostfix(ctx); err != nil {
		g.Log().Error(ctx, "sync bcc config failed: {}", err)
		res.SetError(gerror.New(public.LangCtx(ctx, "modify success but sync config failed: {}", err.Error())))
		return res, nil
	}

	if req.Type != "" && req.Address != "" && req.Goto != "" {
		_ = public.WriteLog(ctx, public.LogParams{
			Type: consts.LOGTYPE.BCC,
			Log:  "Modify bcc rule :" + req.Address + " successfully",
			Data: req,
		})
		res.SetSuccess(public.LangCtx(ctx, "modify bcc rule success"))
	} else {
		if req.Active == 1 {
			_ = public.WriteLog(ctx, public.LogParams{
				Type: consts.LOGTYPE.BCC,
				Log:  "Bcc rule:" + req.Address + " enabled",
				Data: req,
			})
			res.SetSuccess(public.LangCtx(ctx, "bcc rule enabled"))
		} else {
			_ = public.WriteLog(ctx, public.LogParams{
				Type: consts.LOGTYPE.BCC,
				Log:  "Bcc rule:" + req.Address + " disabled",
				Data: req,
			})
			res.SetSuccess(public.LangCtx(ctx, "bcc rule disabled"))
		}
	}

	return res, nil
}
