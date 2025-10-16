package mail_services

import (
	"billionmail-core/internal/consts"
	docker "billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"context"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/mail_services/v1"
)

func (c *ControllerV1) GetPostfixQueueInfo(ctx context.Context, req *v1.GetPostfixQueueInfoReq) (res *v1.GetPostfixQueueInfoRes, err error) {
	res = &v1.GetPostfixQueueInfoRes{}
	if req.QueueID == "" {
		res.SetError(gerror.New(public.LangCtx(ctx, "queue_id required")))
		return res, nil
	}
	dk, dockerErr := docker.NewDockerAPI()
	if dockerErr != nil {
		g.Log().Error(ctx, "Failed to connect to Docker API:", dockerErr)
		res.SetError(gerror.New(public.LangCtx(ctx, "docker api unavailable: {}", dockerErr.Error())))
		return res, nil
	}
	defer dk.Close()
	cmd := []string{"postcat", "-q", req.QueueID}
	result, err := dk.ExecCommandByName(ctx, consts.SERVICES.Postfix, cmd, "root")
	if err != nil {
		g.Log().Error(ctx, "Failed to execute command in container :", err, "command:", strings.Join(cmd, " "))
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to execute command in container: {}", err.Error())))
		return res, nil
	}
	if result == nil {
		g.Log().Error(ctx, "The result of the command is empty:", "command:", strings.Join(cmd, " "))
		res.SetError(gerror.New(public.LangCtx(ctx, "The result of the command is empty: {}", strings.Join(cmd, " "))))
		return res, nil
	}
	if result.ExitCode != 0 {
		g.Log().Error(ctx, "The command execution returns a nonzero status:", result.ExitCode, "output:", result.Output, "command:", strings.Join(cmd, " "))
		res.SetError(gerror.New(public.LangCtx(ctx, "Command execution failed, exit code: {}, output: {}", result.ExitCode, result.Output)))
		return res, nil
	}
	res.Data = result.Output
	res.SetSuccess(public.LangCtx(ctx, "Success"))
	return res, nil
}
