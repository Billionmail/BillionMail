package campaign

import (
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/mail_service"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"net/url"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/util/grand"
	"time"

	"billionmail-core/api/campaign/v1"
)

func (c *ControllerV1) Form(ctx context.Context, req *v1.FormReq) (res *v1.FormRes, err error) {
	r := g.RequestFromCtx(ctx)

	if r.Method == "POST" {
		// Verify Csrf token if needed
		if req.Token == "" {
			r.Response.WriteStatus(400, "CSRF token not provided")
			return
		}

		var v *g.Var
		if v, err = r.Session.Get("csrf_token"); err != nil {
			r.Response.WriteStatus(400, "CSRF token not valid")
			return
		}

		if v.String() != req.Token {
			r.Response.WriteStatus(400, "CSRF token not valid")
			return
		}

		// Clear CSRF token from session
		if err = r.Session.Remove("csrf_token"); err != nil {
			r.Response.WriteStatus(500, "Failed to clear CSRF token")
			return
		}

		contacts := make([]*entity.Contact, 0, len(req.GroupIds))

		for _, groupId := range req.GroupIds {
			contacts = append(contacts, &entity.Contact{
				Email:      req.Email,
				GroupId:    groupId,
				Active:     1,
				CreateTime: int(time.Now().Unix()),
				Attribs: map[string]string{
					"Username": req.Name,
				},
			})
		}

		cnt, _ := contact.BatchCreateContactsIgnoreDuplicate(ctx, contacts)

		if cnt > 0 {
			// Send confirmation email to the user
			go func() {
				if err := sendConfirmationEmail(ctx, req.Email, req.Name); err != nil {
					g.Log().Warning(ctx, "Failed to send confirmation email to %s: %v", req.Email, err)
				}
			}()
		}

		err = r.Response.WriteTpl("subscription_success.html", g.Map{
			"EmailAddress": req.Email,
		})
		return
	}

	// Generate CSRF token
	csrfToken := grand.S(16)

	// Store CSRF token in session
	if err = r.Session.Set("csrf_token", csrfToken); err != nil {
		csrfToken = ""
	}

	groups, _ := contact.GetAllGroups(ctx, "")

	err = r.Response.WriteTpl("subscription_form.html", g.Map{
		"Groups":    groups,
		"CSRFToken": csrfToken,
	})
	return
}

// sendConfirmationEmail sends a confirmation email to the newly subscribed user
func sendConfirmationEmail(ctx context.Context, email, name string) error {
	// Get the base domain to construct noreply email
	baseURL := domains.GetBaseURL()
	if baseURL == "" {
		return fmt.Errorf("base URL not configured")
	}

	// Extract domain from base URL
	domain := ""
	if u, err := url.Parse(baseURL); err == nil && u.Hostname() != "" {
		domain = u.Hostname()
	} else {
		// Fallback: try to get from environment
		if hostname, err := public.DockerEnv("BILLIONMAIL_HOSTNAME"); err == nil && hostname != "" {
			domain = hostname
		} else {
			return fmt.Errorf("unable to determine domain for noreply email")
		}
	}

	// Construct noreply email address
	noreplyEmail := fmt.Sprintf("noreply@%s", domain)

	// Create email sender
	sender, err := mail_service.NewEmailSenderWithLocal(noreplyEmail)
	if err != nil {
		return fmt.Errorf("failed to create email sender: %w", err)
	}
	defer sender.Close()

	// Create confirmation email content
	subject := "Welcome! Your subscription has been confirmed"
	content := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Subscription Confirmed</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #20a53a; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to Our Newsletter!</h1>
        </div>
        <div class="content">
            <p>Dear %s,</p>
            <p>Thank you for subscribing to our newsletter! Your subscription has been successfully confirmed.</p>
            <p>You will now receive our latest updates, news, and exclusive content directly to your inbox.</p>
            <p>If you have any questions or need assistance, please don't hesitate to contact us.</p>
            <p>Best regards,<br>The Team</p>
        </div>
        <div class="footer">
            <p>This email was sent to %s</p>
            <p>Powered by BillionMail</p>
        </div>
    </div>
</body>
</html>`, name, email)

	// Create email message
	message := mail_service.NewMessage(subject, content)
	message.SetMessageID(sender.GenerateMessageID())
	message.SetRealName("Newsletter Team")

	// Send the email
	err = sender.Send(message, []string{email})
	if err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	g.Log().Info(ctx, "Confirmation email sent successfully to %s", email)
	return nil
}
