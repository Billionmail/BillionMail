package mail_boxes

import (
	"billionmail-core/api/mail_boxes/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/mail_boxes"
	"billionmail-core/internal/service/public"
	"context"
	"strings"
)

func (c *ControllerV1) UpdateMailbox(ctx context.Context, req *v1.UpdateMailboxReq) (res *v1.UpdateMailboxRes, err error) {
	res = &v1.UpdateMailboxRes{}
	req.FullName = strings.TrimSpace(req.FullName)
	req.LocalPart = strings.TrimSpace(req.LocalPart)
	mailbox := &v1.Mailbox{
		Username:  req.LocalPart + "@" + req.Domain,
		Password:  req.Password, // If empty, password won't be updated
		FullName:  req.FullName,
		IsAdmin:   req.IsAdmin,
		Quota:     int64(req.Quota),
		LocalPart: req.LocalPart,
		Domain:    req.Domain,
		Active:    req.Active,
	}
	if mailbox.FullName == "" {
		mailbox.FullName = req.LocalPart
	}
	if err = mail_boxes.Update(ctx, mailbox); err != nil {
		return nil, err
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Mailboxes,
		Log:  "Updated mailbox:" + mailbox.Username + " successfully",
		Data: mailbox,
	})
	res.SetSuccess("Mailbox updated successfully")
	return
}
