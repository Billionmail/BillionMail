package domains

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/multi_ip_domain"
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/rbac"
	"context"
	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"time"

	"billionmail-core/api/domains/v1"
)

func (c *ControllerV1) AddDomain(ctx context.Context, req *v1.AddDomainReq) (res *v1.AddDomainRes, err error) {
	res = &v1.AddDomainRes{}

	if req.Hostname == "" {
		req.Hostname = public.FormatMX(req.Domain)
	}

	domain := &v1.Domain{
		Domain:       req.Domain,
		ARecord:      req.Hostname,
		Mailboxes:    req.Mailboxes,
		MailboxQuota: int64(req.MailboxQuota),
		Quota:        int64(req.Quota),
		RateLimit:    req.RateLimit,
		Catchall:     req.Catchall,
		Urls:         req.Urls,
		HasBrandInfo: req.HasBrandInfo,
	}

	if err = domains.Add(ctx, domain); err != nil {
		return nil, err
	}

	// Automatic Certificate Application
	gtimer.AddOnce(500*time.Millisecond, func() {
		acc, accErr := rbac.GetCurrentAccount(ctx)
		if accErr == nil {
			certErr := domains.ApplyLetsEncryptCertWithHttp(ctx, req.Domain, acc)
			if certErr != nil {
				g.Log().Debugf(ctx, "Domain name [%s] added successfully, but auto-request certificate failed: %v", req.Domain, certErr)
			}
		} else {
			g.Log().Debugf(ctx, "The domain name [%s] was added successfully, but the current account failed to obtain the certificate automatically: %v", req.Domain, accErr)
		}

	})
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Domain,
		Log:  "Add domain :" + req.Domain + " successfully",
		Data: domain,
	})

	// If there is a dedicated IP, add the dedicated IP
	if req.OutboundIp != "" {
		err = multi_ip_domain.MultiIPDomainServiceInstance.AddConfig(ctx, req.Domain, req.OutboundIp)
		if err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to add dedicated IP: {}", err.Error())))
			return res, nil
		}

		_ = public.WriteLog(ctx, public.LogParams{
			Type: consts.LOGTYPE.Domain,
			Log:  "Added dedicated sending IP for domain: " + req.Domain + " -> " + req.OutboundIp,
			Data: req,
		})
	}

	res.SetSuccess("Domain added successfully")
	return
}
