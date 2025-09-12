package mail_boxes

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"strings"

	"billionmail-core/api/mail_boxes/v1"
	"billionmail-core/internal/service/mail_boxes"
)

func (c *ControllerV1) AddMailbox(ctx context.Context, req *v1.AddMailboxReq) (res *v1.AddMailboxRes, err error) {
	res = &v1.AddMailboxRes{}
	// 处理参数中的多余空格 FullName  LocalPart
	req.FullName = strings.TrimSpace(req.FullName)
	req.LocalPart = strings.TrimSpace(req.LocalPart)
	mailbox := &v1.Mailbox{
		Username:  req.LocalPart + "@" + req.Domain,
		Password:  req.Password,
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

	if err = mail_boxes.Add(ctx, mailbox); err != nil {
		return nil, err
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Mailboxes,
		Log:  "Add email address :" + req.LocalPart + "@" + req.Domain + " successfully",
		Data: mailbox,
	})

	res.SetSuccess("Mailbox added successfully")
	return
}
