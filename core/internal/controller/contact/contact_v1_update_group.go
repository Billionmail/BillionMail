package contact

import (
	"billionmail-core/api/contact/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"database/sql"
	"fmt"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) UpdateGroup(ctx context.Context, req *v1.UpdateGroupReq) (res *v1.UpdateGroupRes, err error) {
	res = &v1.UpdateGroupRes{}

	updateData := g.Map{}
	if req.Name != "" {
		updateData["name"] = req.Name
	}
	if req.Description != "" {
		updateData["description"] = req.Description
	}
	updateData["double_optin"] = req.DoubleOptin
	updateData["send_welcome_email"] = req.SendWelcomeEmail


	if req.WelcomeHtml != "" {
		updateData["welcome_mail_html"] = req.WelcomeHtml
	}
	if req.WelcomeDrag != "" {
		updateData["welcome_mail_drag"] = req.WelcomeDrag
	}
	if req.ConfirmHtml != "" {
		updateData["confirm_mail_html"] = req.ConfirmHtml
	}
	if req.ConfirmDrag != "" {
		updateData["confirm_mail_drag"] = req.ConfirmDrag
	}
	if req.SuccessUrl != "" {
		updateData["success_url"] = req.SuccessUrl
	}
	if req.ConfirmUrl != "" {
		updateData["confirm_url"] = req.ConfirmUrl
	}
	if req.AlreadyUrl != "" {
		updateData["already_url"] = req.AlreadyUrl
	}
	//if req.SubscribeForm != "" {
	//	updateData["subscribe_form"] = req.SubscribeForm
	//}

	if req.WelcomeSubject != "" {
		updateData["welcome_subject"] = req.WelcomeSubject
	}
	if req.ConfirmSubject != "" {
		updateData["confirm_subject"] = req.ConfirmSubject
	}


	if len(updateData) == 0 {
		res.Code = 400
		res.SetError(gerror.New(public.LangCtx(ctx, "No fields to update")))
		return
	}

	oldGroup, err := contact.GetGroup(ctx, req.GroupId)
	if err != nil && err != sql.ErrNoRows {
		res.Code = 404
		res.SetError(gerror.New(public.LangCtx(ctx, "Group not found")))
		return
	}

	err = contact.UpdateGroup(ctx, req.GroupId, updateData)
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to update group: {}", err.Error())))
		return
	}
	var log string
	if req.Name != "" {
		log = fmt.Sprintf("Updated group: %s successfully", req.Name)
	} else {
		//Update the subscription link Settings for group aad
		log = fmt.Sprintf("Update the subscription link Settings for group: %s ", oldGroup.Name)
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.ContactsGroup,
		Log:  log,
		Data: updateData,
	})

	res.SetSuccess(public.LangCtx(ctx, "Group updated successfully"))
	return
}
