package relay

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/relay"
	"context"

	"billionmail-core/api/relay/v1"
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/public"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"time"
)

func (c *ControllerV1) UpdateRelayConfig(ctx context.Context, req *v1.UpdateRelayConfigReq) (res *v1.UpdateRelayConfigRes, err error) {
	res = &v1.UpdateRelayConfigRes{}
	data := g.Map{}

	var relayInfo *entity.BmRelay
	err = g.DB().Model("bm_relay").Where("id", req.ID).Scan(&relayInfo)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to query relay configuration: {}", err.Error())))
		return res, nil
	}
	if relayInfo == nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Relay configuration does not exist")))
		return res, nil
	}

	// If we updated the sender domain, check for conflicts with other records
	if req.SenderDomain != "" && req.SenderDomain != relayInfo.SenderDomain {
		count, err := g.DB().Model("bm_relay").Where("sender_domain", req.SenderDomain).Where("id != ?", req.ID).Count()
		if err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check domain uniqueness: {}", err.Error())))
			return res, nil
		}
		if count > 0 {
			res.SetError(gerror.New(public.LangCtx(ctx, "Sender domain already exists")))
			return res, nil
		}
		data["sender_domain"] = req.SenderDomain
	}

	if req.AuthPassword != "" {
		encryptedPass, err := relay.EncryptPassword(ctx, req.AuthPassword)
		if err != nil {
			res.SetError(err)
			return res, nil
		}
		data["auth_password"] = encryptedPass
	}

	now := time.Now()
	data["update_time"] = int(now.Unix())
	data["active"] = req.Active

	if req.Remark != "" {
		data["remark"] = req.Remark
	}
	if req.Rtype != "" {
		data["rtype"] = req.Rtype
	}
	if req.RelayHost != "" {
		data["relay_host"] = req.RelayHost
	}
	if req.RelayPort != "" {
		data["relay_port"] = req.RelayPort
	}
	if req.AuthUser != "" {
		data["auth_user"] = req.AuthUser
	}
	if req.IP != "" {
		data["ip"] = req.IP
	}
	if req.Host != "" {
		data["host"] = req.Host
	}

	if req.AuthMethod != "" {
		data["auth_method"] = req.AuthMethod
	}
	if req.TlsProtocol != "" {
		data["tls_protocol"] = req.TlsProtocol
	}
	if req.SkipTlsVerify != 0 {
		data["skip_tls_verify"] = req.SkipTlsVerify
	}
	if req.HeloName != "" {
		data["helo_name"] = req.HeloName
	}
	if req.SmtpName != "" {
		data["smtp_name"] = req.SmtpName
	}
	if req.HeaderJson != "" {
		data["header_json"] = req.HeaderJson
	}
	if req.MaxConcurrency != 0 {
		data["max_concurrency"] = req.MaxConcurrency
	}
	if req.MaxRetries != 0 {
		data["max_retries"] = req.MaxRetries
	}
	if req.MaxIdleTime != "" {
		data["max_idle_time"] = req.MaxIdleTime
	}
	if req.MaxWaitTime != "" {
		data["max_wait_time"] = req.MaxWaitTime
	}

	if len(data) <= 1 {
		res.SetSuccess(public.LangCtx(ctx, "No content needs to be updated"))
		return res, nil
	}

	_, err = g.DB().Model("bm_relay").Where("id", req.ID).Update(data)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to update relay configuration: {}", err.Error())))
		return res, nil
	}

	var updatedRelay *entity.BmRelay
	err = g.DB().Model("bm_relay").Where("id", req.ID).Scan(&updatedRelay)
	if err != nil {
		g.Log().Warning(ctx, "The query for the updated record failed: ", err.Error())
	}

	spfRecord := ""
	if updatedRelay != nil {
		spfRecord = relay.GenerateSPFRecord(updatedRelay.Ip, updatedRelay.Host, updatedRelay.SenderDomain)
	}

	if err := relay.SyncRelayConfigsToPostfix(ctx); err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Updated successfully but failed to sync configuration: {}", err.Error())))
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
		Log:  "Relay configuration updated successfully :" + req.SmtpName + "--" + relayInfo.SenderDomain,
		Data: data,
	})

	if req.Active == 1 {
		res.SetSuccess(public.LangCtx(ctx, "Relay configuration updated and enabled successfully"))
	} else if req.Active == 0 {
		res.SetSuccess(public.LangCtx(ctx, "Relay configuration updated and disabled successfully"))
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Relay configuration updated successfully"))
	}

	return res, nil
}
