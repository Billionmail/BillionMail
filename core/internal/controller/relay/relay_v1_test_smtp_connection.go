package relay

import (
	"billionmail-core/api/relay/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"billionmail-core/internal/service/relay"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
)

// TestSmtpConnection
func (c *ControllerV1) TestSmtpConnection(ctx context.Context, req *v1.TestSmtpConnectionReq) (res *v1.TestSmtpConnectionRes, err error) {
	res = &v1.TestSmtpConnectionRes{}

	result := relay.TestSmtpConnection(
		req.RelayHost,
		req.RelayPort,
		req.AuthUser,
		req.AuthPassword,
	)

	if !result.Success {
		res.SetError(gerror.New(public.LangCtx(ctx, result.Message)))
		return res, nil
	}

	res.Data.ServerInfo = result.ServerInfo
	res.Data.TlsStatus = result.TlsStatus
	res.Data.AuthStatus = result.AuthStatus
	res.Data.ConnectionTime = result.ConnectionTime
	res.Data.SupportedAuth = result.SupportedAuth
	res.Data.RecommendConfig = result.RecommendConfig

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.SMTP,
		Log:  "The SMTP connection test was successful :" + req.RelayHost + ":" + req.RelayPort,
		Data: result,
	})

	res.SetSuccess(public.LangCtx(ctx, "The SMTP connection test was successful"))

	return res, nil
}
