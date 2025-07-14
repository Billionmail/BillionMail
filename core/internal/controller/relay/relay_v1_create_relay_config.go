package relay

import (
	v1 "billionmail-core/api/relay/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/relay"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"time"
)

func (c *ControllerV1) CreateRelayConfig(ctx context.Context, req *v1.CreateRelayConfigReq) (res *v1.CreateRelayConfigRes, err error) {

	res = &v1.CreateRelayConfigRes{}
	// Check if the domain already exists
	count, err := g.DB().Model("bm_relay").Where("sender_domain", req.SenderDomain).Count()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check relay configuration: {}", err.Error())))
		return res, nil
	}
	if count > 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "Sender domain already exists")))
		return res, nil
	}
	// Encrypt the password
	encryptedPass, err := relay.EncryptPassword(ctx, req.AuthPassword)
	if err != nil {
		res.SetError(err)
		return res, nil
	}

	now := time.Now()
	unixTime := int(now.Unix())

	data := g.Map{}

	data["sender_domain"] = req.SenderDomain
	data["relay_host"] = req.RelayHost
	data["relay_port"] = req.RelayPort
	data["auth_user"] = req.AuthUser
	data["auth_password"] = encryptedPass
	data["ip"] = req.IP
	data["host"] = req.Host
	data["remark"] = req.Remark
	data["create_time"] = unixTime
	data["update_time"] = unixTime
	data["rtype"] = req.Rtype

	if req.Active == 0 {
		data["active"] = 0
	} else {
		data["active"] = 1
	}

	// Authentication method: Default is NONE
	//if req.AuthMethod == "" {
	//	data["auth_method"] = "NONE"
	//} else {
	//	data["auth_method"] = req.AuthMethod
	//}
	// TLS protocol: Default is STARTTLS
	//if req.TlsProtocol == "" {
	//	data["tls_protocol"] = "STARTTLS"
	//} else {
	//	data["tls_protocol"] = req.TlsProtocol
	//}
	// Whether to skip TLS verification: Default is to skip (1)
	//if req.SkipTlsVerify == 0 {
	//	data["skip_tls_verify"] = 0
	//} else {
	//	data["skip_tls_verify"] = 1
	//}
	// HELO hostname: Default is mail.SenderDomain
	if req.HeloName == "" {
		data["helo_name"] = "mail." + req.SenderDomain
	} else {
		data["helo_name"] = req.HeloName
	}
	// SMTP service name: Can be empty, will be auto-generated
	data["smtp_name"] = req.SmtpName
	// Email header JSON: Can be empty
	data["header_json"] = req.HeaderJson
	// Maximum concurrent connections: Use default configuration if not set
	if req.MaxConcurrency <= 0 {
		data["max_concurrency"] = 0
	} else {
		data["max_concurrency"] = req.MaxConcurrency
	}
	// Maximum retry attempts
	if req.MaxRetries <= 0 {
		data["max_retries"] = 0
	} else {
		data["max_retries"] = req.MaxRetries
	}
	// Maximum idle time:
	if req.MaxIdleTime == "" {
		data["max_idle_time"] = ""
	} else {
		data["max_idle_time"] = req.MaxIdleTime
	}

	// Maximum wait time:
	if req.MaxWaitTime == "" {
		data["max_wait_time"] = ""
	} else {
		data["max_wait_time"] = req.MaxWaitTime
	}

	_, err = g.DB().Insert(ctx, "bm_relay", data)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to insert relay configuration: {}", err.Error())))
		return res, nil
	}

	spfRecord := relay.GenerateSPFRecord(req.IP, req.Host, req.SenderDomain)

	if err := relay.SyncRelayConfigsToPostfix(ctx); err != nil {
		errMsg := err.Error()
		res.SetError(gerror.New(public.LangCtx(ctx, "Creation was successful but synchronous configuration failed: {}", errMsg)))
		return res, nil
	}

	if spfRecord != "" {
		res.SPFRecord = v1.DNSRecord{
			Type:  "TXT",
			Host:  "@",
			Value: spfRecord,
		}
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.SMTP,
		Log:  "Relay configuration created successfully :" + req.SmtpName + "--" + req.SenderDomain,
		Data: req,
	})

	if req.Active == 1 {
		res.SetSuccess(public.LangCtx(ctx, "Relay configuration created and enabled successfully"))
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Relay configuration created successfully but not enabled"))
	}

	return res, nil
}
