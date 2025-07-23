package domains

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/domains/v1"
	"billionmail-core/internal/service/domains"
)

func (c *ControllerV1) UpdateDomain(ctx context.Context, req *v1.UpdateDomainReq) (res *v1.UpdateDomainRes, err error) {
	res = &v1.UpdateDomainRes{}

	if req.Domain == "" {
		return nil, gerror.New("Domain cannot be empty")
	}

	updateData := map[string]interface{}{}

	domainName := req.Domain
	updateData["domain"] = domainName

	if req.Catchall != "" {
		updateData["catchall"] = req.Catchall
	}

	if req.Mailboxes > 0 {
		updateData["mailboxes"] = req.Mailboxes
	}

	if req.MailboxQuota > 0 {
		updateData["mailbox_quota"] = req.MailboxQuota
	}

	if req.Quota > 0 {
		updateData["quota"] = req.Quota
	}

	if req.RateLimit > 0 {
		updateData["rate_limit"] = req.RateLimit
	}

	updateData["active"] = req.Active

	// URLs
	if len(req.Urls) > 0 {
		updateData["urls"] = req.Urls
	}
	updateData["hasbrandinfo"] = req.HasBrandInfo

	if err = domains.Update(ctx, updateData); err != nil {
		return nil, err
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Domain,
		Log:  "Update domain :" + req.Domain + " successfully",
		Data: updateData,
	})

	res.SetSuccess("Domain updated successfully")
	return
}
