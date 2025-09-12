package mail_boxes

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"

	"billionmail-core/api/mail_boxes/v1"
	"billionmail-core/internal/service/mail_boxes"
)

func (c *ControllerV1) BatchAddMailbox(ctx context.Context, req *v1.BatchAddMailboxReq) (res *v1.BatchAddMailboxRes, err error) {

	res = &v1.BatchAddMailboxRes{}

	if req.Count > 5000 {
		return nil, fmt.Errorf("You cannot create more than 5000 batches")
	}

	createdEmails, err := mail_boxes.BatchAdd(ctx, req.Domain, req.Quota, req.Count, req.Prefix)
	if err != nil {
		return nil, err
	}

	successMsg := fmt.Sprintf("%d email accounts were successfully created", len(createdEmails))

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Mailboxes,
		Log:  "Batch email creation was successful",
		Data: req,
	})
	res.SetSuccess(successMsg)
	res.Data = createdEmails
	return res, nil
}
