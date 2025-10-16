package contact

import (
	"billionmail-core/api/contact/v1"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
)

func (c *ControllerV1) GetSingleGroupTagContactCount(ctx context.Context, req *v1.GetSingleGroupTagContactCountReq) (res *v1.GetSingleGroupTagContactCountRes, err error) {
	res = &v1.GetSingleGroupTagContactCountRes{}

	if len(req.TagIds) == 0 {
		GroupIds := []int{req.GroupId}
		total, err := contact.GetGroupContactCount(ctx, GroupIds)
		if err != nil {
			res.Code = 500
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get contact count: {}", err.Error())))
			return res, nil
		}
		// Set response data
		res.Data.Total = total
		res.SetSuccess(public.LangCtx(ctx, "Successfully retrieved contact count"))
		return res, nil
	}

	model := g.DB().Model("bm_contacts c").
		Where("c.active", 1).
		Where("c.status", 1)

	if req.GroupId > 0 {
		model = model.Where("c.group_id", req.GroupId)
	}

	if len(req.TagIds) > 0 {
		if req.TagLogic == "AND" {
			// AND logic: contact must have all tags
			for i, tagId := range req.TagIds {
				alias := "ct" + strconv.Itoa(i)
				model = model.InnerJoin(
					"bm_contact_tags "+alias,
					fmt.Sprintf("c.id = %s.contact_id AND %s.tag_id = %d", alias, alias, tagId),
				)
			}
		} else {
			// OR logic: contact must have at least one of the tags
			var inValues []string
			for _, tagId := range req.TagIds {
				inValues = append(inValues, strconv.Itoa(tagId))
			}
			subQuery := fmt.Sprintf(
				"(SELECT DISTINCT contact_id FROM bm_contact_tags WHERE tag_id IN (%s)) ct",
				strings.Join(inValues, ","),
			)
			model = model.InnerJoin(subQuery, "c.id = ct.contact_id")
		}
	}

	total, err := model.Fields("DISTINCT c.id").Count()

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get contact count: {}", err.Error())))
		return
	}

	// Set response data
	res.Data.Total = total
	res.SetSuccess(public.LangCtx(ctx, "Successfully retrieved contact count"))
	return
}
