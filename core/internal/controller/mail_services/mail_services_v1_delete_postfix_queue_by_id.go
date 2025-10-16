package mail_services

import (
	"billionmail-core/internal/consts"
	docker "billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"strings"

	"billionmail-core/api/mail_services/v1"
)

func (c *ControllerV1) DeletePostfixQueueById(ctx context.Context, req *v1.DeletePostfixQueueByIdReq) (res *v1.DeletePostfixQueueByIdRes, err error) {
	res = &v1.DeletePostfixQueueByIdRes{}

	dockerApi, err := docker.NewDockerAPI()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "docker api unavailable: {}", err.Error())))
		return res, nil
	}

	if len(req.QueueIDs) == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "No queue IDs provided")))
		return res, nil
	}

	failed := make([]string, 0)
	success := make([]string, 0)
	for _, queueID := range req.QueueIDs {
		_, err = dockerApi.ExecCommandByName(ctx, "postfix", []string{"postsuper", "-d", queueID}, "root")
		if err != nil {
			failed = append(failed, queueID)
			continue
		}
		success = append(success, queueID)
	}

	if len(failed) > 0 {
		if len(success) > 0 {
			_ = public.WriteLog(ctx, public.LogParams{
				Type: consts.LOGTYPE.PostfixQueue,
				Log:  "Delete postfix queue mail " + strings.Join(success, ",") + " successfully",
			})
		}
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete some queue mails: {}", failed)))
		return res, nil
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.PostfixQueue,
		Log:  "Delete postfix queue mail " + strings.Join(req.QueueIDs, ",") + " successfully",
	})

	res.SetSuccess(public.LangCtx(ctx, "delete postfix queue mails success"))
	return res, nil
}
