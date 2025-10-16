package tags

import (
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/tags/v1"
)

func (c *ControllerV1) TagAll(ctx context.Context, req *v1.TagAllReq) (res *v1.TagAllRes, err error) {
	res = &v1.TagAllRes{}

	model := g.DB().Model("bm_tags")
	total, err := model.Count()
	if err != nil {
		return nil, err
	}

	tagList := make([]*entity.Tag, 0)
	err = model.Order("create_time DESC").
		Scan(&tagList)

	if err != nil {
		return nil, err
	}

	for _, tag := range tagList {

		// check if group exists
		GroupInfo, err := contact.GetGroup(ctx, tag.GroupId)

		if err != nil || GroupInfo == nil {
			tag.GroupName = "Unknown"
		} else {
			tag.GroupName = GroupInfo.Name
		}

	}

	res.Data.Total = total
	res.Data.List = tagList
	res.SetSuccess(public.LangCtx(ctx, "Get tag list successfully"))
	return
}
