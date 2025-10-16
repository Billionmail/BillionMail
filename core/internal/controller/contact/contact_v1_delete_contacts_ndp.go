package contact

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"strings"

	"billionmail-core/api/contact/v1"
)

func (c *ControllerV1) DeleteContactsNDP(ctx context.Context, req *v1.DeleteContactsNDPReq) (res *v1.DeleteContactsNDPRes, err error) {
	res = &v1.DeleteContactsNDPRes{}

	if len(req.Ids) == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "The Ids field is required")))
		return
	}
	var contacts []*entity.Contact
	_ = g.DB().Model("bm_contacts").WhereIn("id", req.Ids).Scan(&contacts)
	// Extract all emails
	emails := make([]string, 0, len(contacts))
	for _, contact := range contacts {
		emails = append(emails, contact.Email)
	}
	emailsStr := strings.Join(emails, ", ")

	_, err = g.DB().Model("bm_contacts").WhereIn("id", req.Ids).Delete()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete contacts: {}", err.Error())))
		return
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Contacts,
		Log:  "Delete contacts successfully :" + emailsStr,
		Data: contacts,
	})
	res.SetSuccess(public.LangCtx(ctx, "Contacts deleted successfully"))
	return
}
