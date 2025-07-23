package dockerapi

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/frame/g"
	"time"

	"billionmail-core/api/dockerapi/v1"
)

func (c *ControllerV1) RestartContainer(ctx context.Context, req *v1.RestartContainerReq) (res *v1.RestartContainerRes, err error) {
	res = &v1.RestartContainerRes{}

	gtimer.AddOnce(500*time.Millisecond, func() {
		err = public.DockerApiFromCtx(ctx).RestartContainer(context.Background(), req.ContainerID)

		if err != nil {
			g.Log().Error(ctx, "RestartContainer error:", err)
			return
		}
	})

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.DockerApi,
		Log:  fmt.Sprintf("Restart container: %s successfully", req.ContainerID),
	})

	res.SetSuccess(public.LangCtx(ctx, "Success"))

	return
}
