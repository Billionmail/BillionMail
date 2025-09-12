package contact

import (
	"billionmail-core/api/contact/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"strings"
)

func (c *ControllerV1) DeleteGroup(ctx context.Context, req *v1.DeleteGroupReq) (res *v1.DeleteGroupRes, err error) {
	res = &v1.DeleteGroupRes{}

	var groupNames []string
	var groupInfos []entity.ContactGroup

	for _, groupId := range req.GroupIds {

		groupInfo, errGet := contact.GetGroup(ctx, groupId)
		if errGet != nil {
			res.Data.FailedCount++
			continue
		}

		err = contact.DeleteContactsByGroupId(ctx, groupId)
		if err != nil {
			continue
		}

		err = contact.DeleteGroup(ctx, groupId)
		if err != nil {
			res.Data.FailedCount++
			continue
		}
		res.Data.SuccessCount++

		// 收集分组信息用于日志
		groupNames = append(groupNames, groupInfo.Name)
		groupInfos = append(groupInfos, *groupInfo)
	}
	if res.Data.SuccessCount == 0 && res.Data.FailedCount == 0 {
		res.Code = 400
		res.SetError(gerror.New(public.LangCtx(ctx, "No groups were deleted")))
		return
	}

	groupStr := strings.Join(groupNames, ", ")
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.ContactsGroup,
		Log:  "Deleted group successfully: " + groupStr,
		Data: groupInfos,
	})

	res.SetSuccess(public.LangCtx(ctx, "Groups deleted successfully"))

	return
}
