package contact

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"strings"

	"billionmail-core/api/contact/v1"
)

func (c *ControllerV1) DeleteContacts(ctx context.Context, req *v1.DeleteContactsReq) (res *v1.DeleteContactsRes, err error) {
	res = &v1.DeleteContactsRes{}

	if len(req.Emails) == 0 {
		res.Code = 400
		res.SetError(gerror.New(public.LangCtx(ctx, "The Emails field is required")))
		return
	}

	if req.Status != 0 && req.Status != 1 {
		res.Code = 400
		res.SetError(gerror.New(public.LangCtx(ctx, "The Status must be 0 or 1")))
		return
	}

	// Start a transaction
	err = g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {

		result, err := g.DB().Model("bm_contacts").
			Where("email IN(?)", req.Emails).
			Where("active", req.Status).
			Delete()
		if err != nil {
			return err
		}

		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}

		res.Data.DeletedCount = int(affected)
		return nil
	})

	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete contacts: {}", err.Error())))
		return
	}
	emailsStr := strings.Join(req.Emails, ", ")
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Contacts,
		Log:  "Delete contacts :" + emailsStr + " successfully",
		Data: req.Emails,
	})
	res.SetSuccess(public.LangCtx(ctx, "Contacts deleted successfully"))
	return
}
