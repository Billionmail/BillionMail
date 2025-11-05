package domains

import (
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/public"
	"context"
	"time"

	"billionmail-core/api/domains/v1"

	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) CheckBlacklist(ctx context.Context, req *v1.CheckBlacklistReq) (res *v1.CheckBlacklistRes, err error) {
	res = &v1.CheckBlacklistRes{}
	ip, err := domains.ResolveA(req.ARecord, nil)
	if err != nil {
		return nil, err
	}
	if ip == "127.0.0.1" {
		ip, err = public.GetLocalIP()
		if err != nil {
			ip = "127.0.0.1"
		}
	}

	dnsServers := []string{"8.8.8.8", "1.1.1.1"}

	gtimer.AddOnce(500*time.Millisecond, func() {
		_, err := domains.IsDomainBlacklisted(ctx, ip, req.ARecord, dnsServers)
		if err != nil {
			g.Log().Error(ctx, "Blacklist check failed: {}", err)
			return
		}
	})

	res.SetSuccess(public.LangCtx(ctx, "The test will take two minutes, so please be patient"))
	return
}
