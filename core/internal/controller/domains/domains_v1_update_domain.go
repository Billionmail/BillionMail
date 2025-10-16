package domains

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/multi_ip_domain"
	"billionmail-core/internal/service/public"
	"context"
	"database/sql"
	"github.com/gogf/gf/v2/frame/g"

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

	if req.Hostname != "" {
		updateData["a_record"] = req.Hostname
	}

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

	// ----------------Dedicated IP configuration for domain------------------
	var dbConfigs v1.MultiIPDomain
	ok := true
	err = g.DB().Model("bm_multi_ip_domain").
		Where("active", 1).
		Where("domain", domainName).
		Scan(&dbConfigs)

	if err != nil && err != sql.ErrNoRows {
		ok = false
	}

	if req.OutboundIp != "" {
		if !ok {
			// If there is no dedicated IP configuration, add a new one
			err = multi_ip_domain.MultiIPDomainServiceInstance.AddConfig(ctx, req.Domain, req.OutboundIp)
			if err == nil {
				_ = public.WriteLog(ctx, public.LogParams{
					Type: consts.LOGTYPE.Domain,
					Log:  "Added dedicated sending IP for domain: " + req.Domain + " -> " + req.OutboundIp,
					Data: req,
				})
			}
		} else {
			// If there is a dedicated IP configuration, check if it matches
			if dbConfigs.OutboundIP != req.OutboundIp {
				// Dedicated IP configuration mismatch, delete the old configuration first, then add the new one
				err = multi_ip_domain.MultiIPDomainServiceInstance.DeleteConfig(ctx, req.Domain)
				if err != nil {
					g.Log().Error(ctx, "Failed to delete old dedicated IP configuration: ", err)
				}
				err = multi_ip_domain.MultiIPDomainServiceInstance.AddConfig(ctx, req.Domain, req.OutboundIp)
				if err != nil {
					g.Log().Error(ctx, "Failed to add new dedicated IP configuration: ", err)
				}
				_ = public.WriteLog(ctx, public.LogParams{
					Type: consts.LOGTYPE.Domain,
					Log:  "Updated dedicated sending IP for domain: " + req.Domain + " -> " + req.OutboundIp,
					Data: req,
				})
			}
		}

	} else {
		if ok {
			// Delete dedicated IP configuration
			err = multi_ip_domain.MultiIPDomainServiceInstance.DeleteConfig(ctx, req.Domain)
			if err == nil {

				_ = public.WriteLog(ctx, public.LogParams{
					Type: consts.LOGTYPE.Domain,
					Log:  "Deleted multi-IP domain configuration: " + req.Domain,
					Data: req,
				})
			}
		}
	}

	res.SetSuccess("Domain updated successfully")
	return
}
