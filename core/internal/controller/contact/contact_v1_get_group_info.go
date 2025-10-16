package contact

import (
	"billionmail-core/internal/service/domains"
	"context"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/contact/v1"
	"billionmail-core/internal/controller/subscribe_list"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) GetGroupInfo(ctx context.Context, req *v1.GetGroupInfoReq) (res *v1.GetGroupInfoRes, err error) {
	res = &v1.GetGroupInfoRes{}

	group, err := contact.GetGroup(ctx, req.GroupId)
	if err != nil || group == nil {
		res.Code = 404
		res.SetError(gerror.New(public.LangCtx(ctx, "Group not found")))
		return res, nil
	}

	hostUrl := domains.GetBaseURL()

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
	if group.WelcomeHtml == "" {
		html, drag := subscribe_list.GetDefaultTemplate(1)
		group.WelcomeHtml = html
		group.WelcomeDrag = drag
	}
	if group.ConfirmHtml == "" {
		html, drag := subscribe_list.GetDefaultTemplate(2)
		group.ConfirmHtml = html
		group.ConfirmDrag = drag
	}
	if group.SuccessUrl == "" {
		group.SuccessUrl = hostUrl + "/subscribe_success.html"
	}
	if group.ConfirmUrl == "" {
		group.ConfirmUrl = hostUrl + "/subscribe_confirm.html"
	}
	if group.AlreadyUrl == "" {
		group.AlreadyUrl = hostUrl + "/already_subscribed.html"
	}
	if group.SubscribeForm == "" {
		group.SubscribeForm = subscribe_list.GetSubscribeFormCode(group.Token)
	}
	if group.WelcomeSubject == "" {
		group.WelcomeSubject = "Welcome Aboard!"
	}
	if group.ConfirmSubject == "" {
		group.ConfirmSubject = "Confirm Your Subscription"
	}
	if group.UnsubscribeMailHtml == "" {
		html, drag := subscribe_list.GetDefaultTemplate(3)
		group.UnsubscribeMailHtml = html
		group.UnsubscribeMailDrag = drag
	}
	if group.UnsubscribeSubject == "" {
		group.UnsubscribeSubject = "You're unsubscribed"
	}
	if group.UnsubscribeRedirectUrl == "" {
		group.UnsubscribeRedirectUrl = hostUrl + "/unsubscribe_success.html"
	}



	DefaultDomain, err := subscribe_list.GetDefaultDomain()
	noreplyEmail := "noreply@" + DefaultDomain
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
		UnsubscribeMailHtml:    group.UnsubscribeMailHtml,
		UnsubscribeMailDrag:    group.UnsubscribeMailDrag,
		UnsubscribeSubject:     group.UnsubscribeSubject,
		UnsubscribeRedirectUrl: group.UnsubscribeRedirectUrl,
		SendUnsubscribeEmail:   group.SendUnsubscribeEmail,
	}

	groupInfo := &v1.ContactGroupInfo{
		ContactGroup:  contactGroup,
		SubscribeLink: hostUrl + "/subscribe_form.html?token=" + group.Token,
		Sender:        noreplyEmail,
	}

	res.Data = groupInfo
	res.SetSuccess(public.LangCtx(ctx, "Group info retrieved successfully"))
	return res, nil
}
