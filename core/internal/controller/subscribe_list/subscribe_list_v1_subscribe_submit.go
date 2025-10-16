package subscribe_list

import (
	"billionmail-core/api/subscribe_list/v1"
	"billionmail-core/internal/service/contact_activity"
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"time"
)

func (c *ControllerV1) SubscribeSubmit(ctx context.Context, req *v1.SubscribeSubmitReq) (res *v1.SubscribeSubmitRes, err error) {
	res = &v1.SubscribeSubmitRes{}

	group, err := getGroupByToken(req.Token)
	if err != nil || group.Id == 0 {
		g.RequestFromCtx(ctx).Response.RedirectTo("/invalid.html", 302)
		return
	}

	hostUrl := domains.GetBaseURL()

	// 2. Find contact by email and group
	contact, err := getContactByEmailAndGroup(req.Email, group.Id)

	if contact.Id != 0 {
		if contact.Active == 0 {
			// Contact exists but unsubscribed, update status to 1 (subscribed)
			err = updateContactStatus(req.Email, group.Id, 1)
			if err != nil {
				res.SetError(gerror.New(public.LangCtx(ctx, "Failed to update contact status")))
				return
			}

			// Update contact activity when user resubscribes
			contact_activity.UpdateActivityByEmailAndGroup(req.Email, group.Id)

			if group.SuccessUrl != "" {
				g.RequestFromCtx(ctx).Response.RedirectTo(group.SuccessUrl, 302)
			} else {
				g.RequestFromCtx(ctx).Response.RedirectTo(fmt.Sprintf("%s/subscribe_success.html", hostUrl), 302)
			}
			return
		}
		if contact.Status == 1 {
			// Update contact activity even when already subscribed (user interaction)
			contact_activity.UpdateActivityByEmailAndGroup(req.Email, group.Id)

			if group.AlreadyUrl != "" {
				g.RequestFromCtx(ctx).Response.RedirectTo(group.AlreadyUrl, 302)
			} else {
				g.RequestFromCtx(ctx).Response.RedirectTo(fmt.Sprintf("%s/already_subscribed.html", hostUrl), 302)
			}
			return
		}
	}

	// 3. Check if double opt-in is enabled
	if group.DoubleOptin == 1 {

		err = addOrUpdateContact(req.Email, group.Id, req.Attribs, 0)
		if err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to add contact")))
			return
		}

		// Update contact activity when user submits subscription (even if pending confirmation)
		contact_activity.UpdateActivityByEmailAndGroup(req.Email, group.Id)

		// 3.2 Send confirmation email
		confirmToken := GenerateConfirmToken(req.Email, group.Token)
		confirmUrl := buildConfirmUrl(confirmToken)
		if group.ConfirmHtml == "" {
			group.ConfirmHtml, _ = GetDefaultTemplate(2)
		}
		if group.ConfirmSubject == "" {
			group.ConfirmSubject = "Confirm Your Subscription"
		}
		gtimer.AddOnce(500*time.Millisecond, func() {
			err = SendMail(ctx, group.ConfirmHtml, req.Email, group.ConfirmSubject, confirmUrl)
			if err != nil {
				g.Log().Error(ctx, "Failed to send confirm email: {}", err)
				return
			}

		})

		// 3.3 Redirect to subscription confirmation page
		if group.ConfirmUrl != "" {
			g.RequestFromCtx(ctx).Response.RedirectTo(group.ConfirmUrl, 302)
		} else {
			g.RequestFromCtx(ctx).Response.RedirectTo(fmt.Sprintf("%s/subscribe_confirm.html", hostUrl), 302)
		}
		return
	} else {
		// Single opt-in (no confirmation required)
		// 4.1 Add or update contact with status=1 (confirmed)
		err = addOrUpdateContact(req.Email, group.Id, req.Attribs, 1)
		if err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to add contact")))
			return
		}

		// Update contact activity when user successfully subscribes
		contact_activity.UpdateActivityByEmailAndGroup(req.Email, group.Id)

		// 4.2 Send welcome email if enabled for the group
		if group.SendWelcomeEmail == 1 {
			if group.WelcomeHtml == "" {
				group.WelcomeHtml, _ = GetDefaultTemplate(1)
			}
			if group.WelcomeSubject == "" {
				group.WelcomeSubject = "Welcome Aboard!"
			}
			gtimer.AddOnce(500*time.Millisecond, func() {
				err = SendMail(ctx, group.WelcomeHtml, req.Email, group.WelcomeSubject, "")
				if err != nil {
					g.Log().Error(ctx, "Failed to send welcome email: {}", err)
					return
				}
			})
		}

		if group.SuccessUrl != "" {
			g.RequestFromCtx(ctx).Response.RedirectTo(group.SuccessUrl, 302)
		} else {
			g.RequestFromCtx(ctx).Response.RedirectTo(fmt.Sprintf("%s/subscribe_success.html", hostUrl), 302)
		}
		return
	}
}
