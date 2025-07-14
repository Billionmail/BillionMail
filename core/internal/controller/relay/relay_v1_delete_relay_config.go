package relay

import (
	"billionmail-core/api/relay/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/relay"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) DeleteRelayConfig(ctx context.Context, req *v1.DeleteRelayConfigReq) (res *v1.DeleteRelayConfigRes, err error) {
	res = &v1.DeleteRelayConfigRes{}

	info, err := g.DB().Model("bm_relay").Where("id", req.ID).One()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to check relay configuration: {}", err.Error())))
		return res, nil
	}
	if info.IsEmpty() {
		res.SetError(gerror.New(public.LangCtx(ctx, "Relay configuration does not exist")))
		return res, nil
	}

	_, err = g.DB().Model("bm_relay").Where("id", req.ID).Delete()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete relay configuration: {}", err.Error())))
		return res, nil
	}
	// Sync configuration to Postfix
	if err := relay.SyncRelayConfigsToPostfix(ctx); err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Deleted successfully but failed to sync configuration: {}", err.Error())))
		return res, nil
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.SMTP,
		Log:  "Relay configuration deleted successfully :" + info["smtp_name"].String() + "--" + info["sender_domain"].String(),
	})

	res.SetSuccess(public.LangCtx(ctx, "Relay configuration deleted successfully"))
	return res, nil
}
