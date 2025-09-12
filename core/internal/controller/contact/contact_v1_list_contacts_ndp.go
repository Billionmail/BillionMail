package contact

import (
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"database/sql"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/contact/v1"
)

func (c *ControllerV1) ListContactsNDP(ctx context.Context, req *v1.ListContactsNDPReq) (res *v1.ListContactsNDPRes, err error) {
	res = &v1.ListContactsNDPRes{}

	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 1000 {
		req.PageSize = 20
	}

	model := g.DB().Model("bm_contacts").Safe()

	if req.GroupId > 0 {
		model = model.Where("group_id", req.GroupId)
	}
	if req.Keyword != "" {
		model = model.WhereLike("email", "%"+req.Keyword+"%")
	}
	if req.Active != -1 {
		model = model.Where("active", req.Active)
	}

	total, err := model.Count()
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get contacts count: {}", err.Error())))
		return
	}

	var list []*v1.Contact
	err = model.Order("create_time DESC").Page(req.Page, req.PageSize).Scan(&list)
	if err != nil && err != sql.ErrNoRows {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get contacts list: {}", err.Error())))
		return
	}

	for email, contactInfo := range list {
		groups, err := contact.GetGroup(ctx, contactInfo.GroupId)
		if err != nil {
			g.Log().Debugf(ctx, "Failed to get groups for contact %s: %v", email, err)
			continue
		}

		contactInfo.GroupName = groups.Name
	}

	res.Data.Total = total
	res.Data.List = list
	res.SetSuccess(public.LangCtx(ctx, "Get contacts list successfully"))
	return
}
