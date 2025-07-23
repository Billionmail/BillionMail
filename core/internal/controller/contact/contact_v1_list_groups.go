package contact

import (
	"billionmail-core/api/contact/v1"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) ListGroups(ctx context.Context, req *v1.ListGroupsReq) (res *v1.ListGroupsRes, err error) {

	res = &v1.ListGroupsRes{}
	// Handle request parameters
	page := req.Page
	if page <= 0 {
		page = DefaultPage
	}

	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}

	// Get group list
	groups, total, err := contact.ContactsGroupWithPage(ctx, page, pageSize, req.Keyword)
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get group list {}", err.Error())))
		return
	}
	//hostUrl := domains.GetBaseURL()
	// Convert group information
	groupInfos := make([]*v1.ContactGroupInfo, 0, len(groups))
	for _, group := range groups {
		// Get statistics information
		activeCount, err := contact.CountContactsByGroup(ctx, group.Id, 1)
		if err != nil {
			activeCount = 0
		}

		unsubscribeCount, err := contact.CountContactsByGroup(ctx, group.Id, 0)
		if err != nil {
			unsubscribeCount = 0
		}

		// If the group token is empty, generate a new token
		if group.Token == "" {

			token := GfMd5Short()
			group.Token = token
			_, err := g.DB().Model("bm_contact_groups").
				Data(g.Map{"token": token}).
				Where("id", group.Id).
				Update()
			if err != nil {
				g.Log().Error(ctx, "Failed to update the group token: %v", err)
			}
		}
		//if group.WelcomeHtml == "" {
		//	html, drag := subscribe_list.GetDefaultTemplate(1)
		//	group.WelcomeHtml = html
		//	group.WelcomeDrag = drag
		//}
		//if group.ConfirmHtml == "" {
		//	html, drag := subscribe_list.GetDefaultTemplate(2)
		//	group.ConfirmHtml = html
		//	group.ConfirmDrag = drag
		//}
		//if group.SuccessUrl == "" {
		//	group.SuccessUrl = hostUrl + "/subscribe_success.html"
		//}
		//if group.ConfirmUrl == "" {
		//	group.ConfirmUrl = hostUrl + "/subscribe_confirm.html"
		//}
		//if group.AlreadyUrl == "" {
		//	group.AlreadyUrl = hostUrl + "/already_subscribed.html"
		//}
		//if group.SubscribeForm == "" {
		//	group.SubscribeForm = subscribe_list.GetSubscribeFormCode(group.Token)
		//}
		//if group.WelcomeSubject == "" {
		//	group.WelcomeSubject = "Welcome Aboard!"
		//}
		//if group.ConfirmSubject == "" {
		//	group.ConfirmSubject = "Confirm Your Subscription"
		//}

		contactGroup := v1.ContactGroup{
			Id:               group.Id,
			Name:             group.Name,
			Description:      group.Description,
			CreateTime:       group.CreateTime,
			UpdateTime:       group.UpdateTime,
			Token:            group.Token,
			DoubleOptin:      group.DoubleOptin,
			WelcomeHtml:      group.WelcomeHtml,
			WelcomeDrag:      group.WelcomeDrag,
			ConfirmHtml:      group.ConfirmHtml,
			ConfirmDrag:      group.ConfirmDrag,
			SuccessUrl:       group.SuccessUrl,
			ConfirmUrl:       group.ConfirmUrl,
			AlreadyUrl:       group.AlreadyUrl,
			SubscribeForm:    group.SubscribeForm,
			ConfirmSubject:   group.ConfirmSubject,
			WelcomeSubject:   group.WelcomeSubject,
			SendWelcomeEmail: group.SendWelcomeEmail,
		}

		// Convert to group information
		groupInfo := &v1.ContactGroupInfo{
			ContactGroup:     contactGroup,
			TotalCount:       activeCount + unsubscribeCount,
			ActiveCount:      activeCount,
			UnsubscribeCount: unsubscribeCount,
			//SubscribeLink:    hostUrl + "/subscribe_form.html?token=" + group.Token,
		}
		groupInfos = append(groupInfos, groupInfo)
	}

	res.Data.Total = total
	res.Data.List = groupInfos
	res.SetSuccess(public.LangCtx(ctx, "Group list retrieved successfully"))
	return

}
