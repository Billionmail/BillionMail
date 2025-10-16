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

func (c *ControllerV1) FlushPostfixQueueById(ctx context.Context, req *v1.FlushPostfixQueueByIdReq) (res *v1.FlushPostfixQueueByIdRes, err error) {
	res = &v1.FlushPostfixQueueByIdRes{}
	if len(req.QueueIDs) == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "queue_ids required")))
		return res, nil
	}
	dk, dockerErr := docker.NewDockerAPI()
	if dockerErr != nil {
		g.Log().Error(ctx, "Failed to connect to Docker API:", dockerErr)
		res.SetError(gerror.New(public.LangCtx(ctx, "docker api unavailable: {}", dockerErr.Error())))
		return res, nil
	}
	defer dk.Close()

	failed := make([]string, 0)
	success := make([]string, 0)
	for _, queueID := range req.QueueIDs {
		cmd := []string{"postqueue", "-i", queueID}
		result, err := dk.ExecCommandByName(ctx, consts.SERVICES.Postfix, cmd, "root")
		if err != nil || result == nil || result.ExitCode != 0 {
			failed = append(failed, queueID)
			continue
		}
		success = append(success, queueID)
	}

	if len(failed) > 0 {
		if len(success) > 0 {
			_ = public.WriteLog(ctx, public.LogParams{
				Type: consts.LOGTYPE.PostfixQueue,
				Log:  "Flush postfix queue mail [" + strings.Join(success, ",") + "] successfully",
			})
		}
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to flush some queue mails: {}", failed)))
		return res, nil
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.PostfixQueue,
		Log:  "Flush postfix queue mail [" + strings.Join(req.QueueIDs, ",") + "] successfully",
	})
	res.SetSuccess(public.LangCtx(ctx, "flush postfix queue mails by id success"))
	return res, nil
}
