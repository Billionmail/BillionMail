package tags

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"database/sql"
	"github.com/gogf/gf/v2/frame/g"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/tags/v1"
)

func (c *ControllerV1) TagCreate(ctx context.Context, req *v1.TagCreateReq) (res *v1.TagCreateRes, err error) {
	res = &v1.TagCreateRes{}

	GroupInfo, err := contact.GetGroup(ctx, req.GroupId)
	if err != nil && err != sql.ErrNoRows {
		res.Code = 404
		res.SetError(gerror.New(public.LangCtx(ctx, "Group not found")))
		return
	}

	count, err := g.DB().Model("bm_tags").Where("group_id", req.GroupId).Where("name", req.Name).Count()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check tag name")))
		return
	}

	if count > 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "Tag name already exists")))
		return
	}

	now := time.Now().Unix()
	_, err = g.DB().Model("bm_tags").
		Ctx(ctx).
		Insert(g.Map{
			"group_id":    req.GroupId,
			"name":        req.Name,
			"create_time": now,
		})
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to create tag")))
		return
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Tag,
		Log:  "Create [" + GroupInfo.Name + "] tag :" + req.Name + " successfully",
		Data: req,
	})

	res.SetSuccess(public.LangCtx(ctx, "Tag created successfully"))
	return
}
