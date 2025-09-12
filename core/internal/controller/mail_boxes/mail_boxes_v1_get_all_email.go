package mail_boxes

import (
	"billionmail-core/internal/service/mail_boxes"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"

	"billionmail-core/api/mail_boxes/v1"
)

func (c *ControllerV1) GetAllEmail(ctx context.Context, req *v1.GetAllEmailReq) (res *v1.GetAllEmailRes, err error) {
	res = &v1.GetAllEmailRes{}

	res.Data, err = mail_boxes.AllEmail(ctx, req.Domain)

	if err != nil {
		err = fmt.Errorf("failed to get all emails: %w", err)
		return
	}

	res.SetSuccess(public.LangCtx(ctx, "Success"))

	return
}
