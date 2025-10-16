package tags

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/frame/g"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/tags/v1"
)

func (c *ControllerV1) TagUpdate(ctx context.Context, req *v1.TagUpdateReq) (res *v1.TagUpdateRes, err error) {

	res = &v1.TagUpdateRes{}

	// 检查标签是否存在
	var tag struct {
		Id      int `json:"id"`
		GroupId int `json:"group_id"`
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

	// 检查标签名是否重复（排除自己）
	var nameCount int
	nameCount, err = g.DB().Model("bm_tags").
		Where("group_id", tag.GroupId).
		Where("name", req.Name).
		Where("id !=", req.Id).
		Count()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check tag name")))
		return
	}
	if nameCount > 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "Tag name already exists")))
		return
	}

	// 更新标签
	_, err = g.DB().Model("bm_tags").
		Ctx(ctx).
		Where("id", req.Id).
		Update(g.Map{
			"name": req.Name,
		})
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to update tag")))
		return
	}

	// 记录操作日志
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Tag,
		Log:  "Update tag: " + req.Name + " successfully",
		Data: req,
	})
	res.SetSuccess(public.LangCtx(ctx, "Tag updated successfully"))
	return
}
