package settings

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/frame/g"
	"net"
	"strings"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/settings/v1"
)

func (c *ControllerV1) AddIPWhitelist(ctx context.Context, req *v1.AddIPWhitelistReq) (res *v1.AddIPWhitelistRes, err error) {
	res = &v1.AddIPWhitelistRes{}

	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		res.SetError(gerror.New(public.LangCtx(ctx, "IP cannot be empty")))
		return
	}
	if net.ParseIP(ip) == nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Invalid IP address: {}", ip)))
		return
	}

	ipType := 1 // IPv4
	if net.ParseIP(ip).To4() == nil {
		ipType = 2 // IPv6
	}

	// Check if already exists
	count, err := g.DB().Model("bm_console_ip_whitelist").Where("ip", ip).Count()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to query IP whitelist: {}", err)))
		return
	}
	if count > 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "This IP is already in the whitelist")))
		return
	}

	_, err = g.DB().Model("bm_console_ip_whitelist").Insert(g.Map{
		"ip":          ip,
		"ip_type":     ipType,
		"create_time": time.Now().Unix(),
	})
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to add IP to whitelist: {}", err)))
		return
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Settings,
		Log:  "Add whitelist ip :" + ip + "successfully",
	})

	res.SetSuccess(public.LangCtx(ctx, "IP added to whitelist successfully"))
	return res, nil
}
