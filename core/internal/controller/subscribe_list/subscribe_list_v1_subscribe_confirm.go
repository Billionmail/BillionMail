package subscribe_list

import (
	"billionmail-core/internal/service/contact_activity"
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"time"

	"billionmail-core/api/subscribe_list/v1"
)

func (c *ControllerV1) SubscribeConfirm(ctx context.Context, req *v1.SubscribeConfirmReq) (res *v1.SubscribeConfirmRes, err error) {
	res = &v1.SubscribeConfirmRes{}

	email, groupToken, err := getEmailFromToken(req.Token)
	if err != nil {
		g.RequestFromCtx(ctx).Response.RedirectTo("/invalid.html", 302)
		return
	}
	if email == "" || groupToken == "" {
		g.RequestFromCtx(ctx).Response.RedirectTo("/invalid.html", 302)
		return
	}

	// 1. Find subscription group
	group, err := getGroupByToken(groupToken)
	if err != nil {
		g.RequestFromCtx(ctx).Response.RedirectTo("/invalid.html", 302)
		return
	}

	// 2. Find contact by email and group
	contact, err := getContactByEmailAndGroup(req.Email, group.Id)
	if err != nil || contact == nil {
		g.RequestFromCtx(ctx).Response.RedirectTo("/invalid.html", 302)
		return
	}
	hostUrl := domains.GetBaseURL()
	if contact.Status == 1 && contact.Active == 1 {
		// Update contact activity even when already confirmed (user interaction)
		contact_activity.UpdateActivityByEmailAndGroup(req.Email, group.Id)

		if group.AlreadyUrl != "" {
			g.RequestFromCtx(ctx).Response.RedirectTo(group.AlreadyUrl, 302)
		} else {
			g.RequestFromCtx(ctx).Response.RedirectTo(fmt.Sprintf("%s/already_subscribed.html", hostUrl), 302)
		}
		return
	}

	// 3. Update contact status to confirmed (status=1, active=1)
	err = updateContactStatus(req.Email, group.Id, 1)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to confirm subscription")))
		return
	}

	// Update contact activity when user confirms subscription
	contact_activity.UpdateActivityByEmailAndGroup(req.Email, group.Id)

	// 5. Send welcome email
	if group.SendWelcomeEmail == 1 {
		if group.WelcomeHtml == "" {
			group.WelcomeHtml, _ = GetDefaultTemplate(1)
		}
		if group.WelcomeSubject == "" {
			group.WelcomeSubject = "Welcome Aboard!"
		}
		gtimer.AddOnce(500*time.Millisecond, func() {
			err = SendMail(ctx, group.WelcomeHtml, email, group.WelcomeSubject, "")
			if err != nil {
				g.Log().Error(ctx, "Failed to send welcome email: {}", err)
				return
			}

		})
	}

	// 6. Redirect to subscription success page
	if group.SuccessUrl != "" {
		g.RequestFromCtx(ctx).Response.RedirectTo(group.SuccessUrl, 302)
	} else {
		g.RequestFromCtx(ctx).Response.RedirectTo(fmt.Sprintf("%s/subscribe_success.html", hostUrl), 302)
	}
	return
}
