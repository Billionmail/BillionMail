package mail_boxes

import (
	"billionmail-core/api/mail_boxes/v1"
	"billionmail-core/internal/service/mail_boxes"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
)

func (c *ControllerV1) GetAllMailbox(ctx context.Context, req *v1.GetAllMailboxReq) (res *v1.GetAllMailboxRes, err error) {
	res = &v1.GetAllMailboxRes{}

	res.Data, err = mail_boxes.All(ctx, req.Domain)

	if err != nil {
		err = fmt.Errorf("failed to get all mailboxes: %w", err)
		return
	}

	res.SetSuccess(public.LangCtx(ctx, "Success"))

	return
}
