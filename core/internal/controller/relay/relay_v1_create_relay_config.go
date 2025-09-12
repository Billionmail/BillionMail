package relay

import (
	v1 "billionmail-core/api/relay/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/relay"
	"context"
	"strings"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) CreateRelayConfig(ctx context.Context, req *v1.CreateRelayConfigReq) (res *v1.CreateRelayConfigRes, err error) {
	res = &v1.CreateRelayConfigRes{}

	if len(req.SenderDomains) > 0 {

		var domains []string
		for _, domain := range req.SenderDomains {

			domains = append(domains, domain)
		}

		count, err := g.DB().Model("bm_relay_domain_mapping").WhereIn("sender_domain", domains).Count()
		if err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check domain mapping: {}", err.Error())))
			return res, nil
		}
		if count > 0 {
			res.SetError(gerror.New(public.LangCtx(ctx, "One or more sender domains already exist")))
			return res, nil
		}
	}

	encryptedPass, err := relay.EncryptPassword(ctx, req.AuthPassword)
	if err != nil {
		res.SetError(err)
		return res, nil
	}

	now := time.Now()
	unixTime := int(now.Unix())

	if req.AuthMethod == "" {
		req.AuthMethod = "NONE"
	}

	configData := g.Map{
		"remark":          req.Remark,
		"rtype":           req.Rtype,
		"relay_host":      req.RelayHost,
		"relay_port":      req.RelayPort,
		"auth_user":       req.AuthUser,
		"auth_password":   encryptedPass,
		"ip":              req.IP,
		"host":            req.Host,
		"active":          req.Active,
		"auth_method":     req.AuthMethod,
		"tls_protocol":    req.TlsProtocol,
		"skip_tls_verify": req.SkipTlsVerify,
		"helo_name":       req.HeloName,
		"smtp_name":       req.SmtpName,
		"create_time":     unixTime,
		"update_time":     unixTime,
	}

	tx, err := g.DB().Begin(ctx)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to start transaction: {}", err.Error())))
		return res, nil
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	result, err := tx.Model("bm_relay_config").Data(configData).Insert()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to create relay configuration: {}", err.Error())))
		return res, nil
	}

	relayId, err := result.LastInsertId()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get inserted ID: {}", err.Error())))
		return res, nil
	}

	for _, domain := range req.SenderDomains {

		mappingData := g.Map{
			"relay_id":      relayId,
			"sender_domain": domain,
			"create_time":   unixTime,
		}

		_, err = tx.Model("bm_relay_domain_mapping").Data(mappingData).Insert()
		if err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to create domain mapping: {}", err.Error())))
			return res, nil
		}
	}

	err = tx.Commit()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to commit transaction: {}", err.Error())))
		return res, nil
	}

	if err = relay.SyncRelayConfigsToPostfix(ctx); err != nil {
		g.Log().Error(ctx, "Failed to sync relay configs to Postfix:", err)
	}

	if len(req.SenderDomains) > 0 {
		domain := req.SenderDomains[0]
		if strings.HasPrefix(domain, "@") {
			domain = domain[1:]
		}
		spfValue := relay.GenerateSPFRecord(req.IP, req.Host, domain)
		res.SPFRecord = v1.DNSRecord{
			Type:  "TXT",
			Host:  domain,
			Value: spfValue,
		}
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.SMTP,
		Log:  "Created relay configuration: " + req.SmtpName + " for domains: " + strings.Join(req.SenderDomains, ", "),
	})

	res.SetSuccess(public.LangCtx(ctx, "Relay configuration created successfully"))
	return res, nil
}
