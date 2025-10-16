package tags

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/frame/g"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/tags/v1"
)

func (c *ControllerV1) TagDelete(ctx context.Context, req *v1.TagDeleteReq) (res *v1.TagDeleteRes, err error) {
	res = &v1.TagDeleteRes{}

	// 检查标签是否存在
	var tag struct {
		Id   int    `json:"id"`
		Name string `json:"name"`
	}
	err = g.DB().Model("bm_tags").Where("id", req.Id).Scan(&tag)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check tag")))
		return
	}
	if tag.Id == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "Tag not found")))
		return
	}

	// 检查是否有联系人使用该标签 todo 删除标签同时删除关联
	var contactCount int
	contactCount, err = g.DB().Model("bm_contact_tags").Where("tag_id", req.Id).Count()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check tag usage")))
		return
	}
	if contactCount > 0 {
		// 删除关联
		_, err = g.DB().Model("bm_contact_tags").
			Ctx(ctx).
			Where("tag_id", req.Id).
			Delete()
		if err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete tag associations")))
			return
		}
		//res.SetError(gerror.New(public.LangCtx(ctx, "Cannot delete tag that is in use")))
		//return
	}

	// 删除标签
	_, err = g.DB().Model("bm_tags").
		Ctx(ctx).
		Where("id", req.Id).
		Delete()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete tag")))
		return
	}

	// 记录操作日志
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Tag,
		Log:  "Delete tag: " + tag.Name + " successfully",
		Data: req,
	})

	res.SetSuccess(public.LangCtx(ctx, "Tag deleted successfully"))
	return
}
