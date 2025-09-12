package relay

import (
	"billionmail-core/api/relay/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/relay"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"strings"
)

func (c *ControllerV1) DeleteRelayConfig(ctx context.Context, req *v1.DeleteRelayConfigReq) (res *v1.DeleteRelayConfigRes, err error) {
	res = &v1.DeleteRelayConfigRes{}

	relayInfo, err := g.DB().Model("bm_relay_config").Where("id", req.ID).One()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check relay configuration: {}", err.Error())))
		return res, nil
	}
	if relayInfo.IsEmpty() {
		res.SetError(gerror.New(public.LangCtx(ctx, "Relay configuration does not exist")))
		return res, nil
	}

	var domainMappings []struct {
		SenderDomain string `json:"sender_domain"`
	}
	err = g.DB().Model("bm_relay_domain_mapping").
		Where("relay_id", req.ID).
		Fields("sender_domain").
		Scan(&domainMappings)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to query domain mappings: {}", err.Error())))
		return res, nil
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

	_, err = tx.Model("bm_relay_config").Where("id", req.ID).Delete()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete relay configuration: {}", err.Error())))
		return res, nil
	}

	_, err = tx.Model("bm_relay_domain_mapping").Where("relay_id", req.ID).Delete()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete domain mappings: {}", err.Error())))
		return res, nil
	}

	if err = tx.Commit(); err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to commit transaction: {}", err.Error())))
		return res, nil
	}

	if err := relay.SyncRelayConfigsToPostfix(ctx); err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Deleted successfully but failed to sync configuration: {}", err.Error())))
		return res, nil
	}

	domainsList := []string{}
	for _, mapping := range domainMappings {
		domainsList = append(domainsList, mapping.SenderDomain)
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.SMTP,
		Log:  "Relay configuration deleted successfully: " + relayInfo["smtp_name"].String() + " for domains: " + strings.Join(domainsList, ", "),
	})

	res.SetSuccess(public.LangCtx(ctx, "Relay configuration deleted successfully"))
	return res, nil
}
