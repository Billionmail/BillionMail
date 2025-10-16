package contact

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"database/sql"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/contact/v1"
)

func (c *ControllerV1) UpdateGroupUnsubscribe(ctx context.Context, req *v1.UpdateGroupUnsubscribeReq) (res *v1.UpdateGroupUnsubscribeRes, err error) {
	res = &v1.UpdateGroupUnsubscribeRes{}

	updateData := g.Map{}
	updateData["send_unsubscribe_email"] = req.SendUnsubscribeEmail
	if req.UnsubscribeSubject != "" {
		updateData["unsubscribe_subject"] = req.UnsubscribeSubject
	}
	if req.UnsubscribeMailHtml != "" {
		updateData["unsubscribe_mail_html"] = req.UnsubscribeMailHtml
	}
	if req.UnsubscribeMailDrag != "" {
		updateData["unsubscribe_mail_drag"] = req.UnsubscribeMailDrag
	}
	if req.UnsubscribeRedirectUrl != "" {
		updateData["unsubscribe_redirect_url"] = req.UnsubscribeRedirectUrl
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
	log = fmt.Sprintf("Update the Unsubscribe Settings for group: %s ", oldGroup.Name)

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.ContactsGroup,
		Log:  log,
		Data: updateData,
	})

	res.SetSuccess(public.LangCtx(ctx, "Group updated successfully"))
	return
}
