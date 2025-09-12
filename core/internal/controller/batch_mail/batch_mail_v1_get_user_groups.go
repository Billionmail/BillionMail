package batch_mail

import (
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/batch_mail/v1"
)

func (c *ControllerV1) GetUserGroups(ctx context.Context, req *v1.GetUserGroupsReq) (res *v1.GetUserGroupsRes, err error) {
	res = &v1.GetUserGroupsRes{}

	var groups []*v1.GroupInfo
	err = g.DB().Model("bm_contacts c").
		LeftJoin("bm_contact_groups cg", "c.group_id = cg.id").
		Fields("cg.id, cg.name").
		Where("c.email", req.Email).
		Where("c.active", 1).
		Scan(&groups)
	if err != nil {
		res.SetError(gerror.New("Failed to get user groups: " + err.Error()))
		return
	}

	res.Data = groups
	res.SetSuccess(public.LangCtx(ctx, "Success"))
	return
}
