package batch_mail

import (
	"billionmail-core/api/batch_mail/v1"
	"billionmail-core/internal/service/batch_mail"
	"billionmail-core/internal/service/contact_activity"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"time"
)

func (c *ControllerV1) Unsubscribe(ctx context.Context, req *v1.UnsubscribeReq) (res *v1.UnsubscribeRes, err error) {
	res = &v1.UnsubscribeRes{}

	// Parse JWT token to get user information
	claims, err := batch_mail.ParseUnsubscribeJWT(req.Jwt)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Invalid token")))
		return
	}

	// Log the unsubscribe request
	g.Log().Info(ctx, "Unsubscribe request received - Email: %s, Template: %d, Task: %d, Groups: %v",
		claims.Email, claims.TemplateId, claims.TaskId, req.GroupId)

	// Input validation
	if claims.Email == "" {
		res.SetError(gerror.New(public.LangCtx(ctx, "Email address is required")))
		return
	}

	if len(req.GroupId) == 0 {
		g.Log().Debugf(ctx, "No group IDs provided for unsubscribe - Email: %s", claims.Email)
		res.SetError(gerror.New(public.LangCtx(ctx, "No group IDs provided for unsubscribe")))
		return
	}

	// Begin transaction to ensure data consistency
	err = g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// 1. Update contact status to inactive (unsubscribed)
		for _, groupId := range req.GroupId {
			result, err := tx.Model("bm_contacts").
				Where("email", claims.Email).
				Where("group_id", groupId).
				Data(g.Map{"active": 0}).
				Update()

			// Update contact activity when user unsubscribes (user interaction)
			contact_activity.UpdateActivityByEmailAndGroup(claims.Email, groupId)

			if err != nil {
				g.Log().Error(ctx, "Failed to update contact status: %v", err)
				return err
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				g.Log().Warning(ctx, "No contact record found for email: %s in group: %d", claims.Email, groupId)

			}
		}

		for _, groupId := range req.GroupId {
			_, err = tx.Model("unsubscribe_records").InsertIgnore(g.Map{
				"email":            claims.Email,
				"group_id":         groupId,
				"template_id":      claims.TemplateId,
				"task_id":          claims.TaskId,
				"unsubscribe_time": time.Now().Unix(),
			})

			if err != nil {
				g.Log().Error(ctx, "Failed to record unsubscribe: %v", err)
				return err
			}

		}

		return nil
	})

	if err != nil {

		res.SetError(gerror.New(public.LangCtx(ctx, "Email address is required")))
		return
	}

	res.SetSuccess(public.LangCtx(ctx, "You have been successfully unsubscribed"))
	return
}
