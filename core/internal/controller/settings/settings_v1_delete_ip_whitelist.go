package settings

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/frame/g"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/settings/v1"
)

func (c *ControllerV1) DeleteIPWhitelist(ctx context.Context, req *v1.DeleteIPWhitelistReq) (res *v1.DeleteIPWhitelistRes, err error) {
	res = &v1.DeleteIPWhitelistRes{}

	if req.ID <= 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "ID cannot be empty")))
		return
	}

	// Check if it exists
	info, err := g.DB().Model("bm_console_ip_whitelist").Where("id", req.ID).One()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to query IP whitelist: {}", err)))
		return
	}
	if info.IsEmpty() {
		res.SetError(gerror.New(public.LangCtx(ctx, "The IP whitelist does not exist")))
		return
	}

	_, err = g.DB().Model("bm_console_ip_whitelist").Where("id", req.ID).Delete()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete IP from whitelist: {}", err)))
		return
	}

	//  Check whether the whitelist is empty, if it is empty, then automatically turn off the ip whitelist switch
	count, err := g.DB().Model("bm_console_ip_whitelist").Count()
	if err == nil && count == 0 {
		err = public.SetDockerEnv("IP_WHITELIST_ENABLE", "false")
		if err != nil {
			g.Log().Error(ctx, "Failed to set IP whitelist enable: {}", err)
		}
		gtimer.AddOnce(500*time.Millisecond, func() {
			err = public.DockerApiFromCtx(ctx).RestartContainerByName(ctx, consts.SERVICES.Core)
			if err != nil {
				g.Log().Error(ctx, "Failed to restart container: {}", err)
				return
			}

		})
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Settings,
		Log:  "Removed whitelist ip :" + info["ip"].String() + "successfully",
	})
	res.SetSuccess(public.LangCtx(ctx, "IP removed from whitelist successfully"))
	return res, nil
}
