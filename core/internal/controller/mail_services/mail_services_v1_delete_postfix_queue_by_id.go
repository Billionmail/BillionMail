package mail_services

import (
	"billionmail-core/internal/consts"
	docker "billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/mail_services/v1"
)

func (c *ControllerV1) DeletePostfixQueueById(ctx context.Context, req *v1.DeletePostfixQueueByIdReq) (res *v1.DeletePostfixQueueByIdRes, err error) {
	res = &v1.DeletePostfixQueueByIdRes{}

	dockerApi, err := docker.NewDockerAPI()

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "docker api unavailable: {}", err.Error())))
		return res, nil
	}
	_, err = dockerApi.ExecCommandByName(ctx, "postfix", []string{"postsuper", "-d", req.QueueID}, "root")
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "postsuper -d failed: {}", err.Error())))
		return res, nil
	}
	// Operation Log
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.PostfixQueue,
		Log:  "Delete postfix queue mail " + req.QueueID + " successfully",
	})

	res.SetSuccess(public.LangCtx(ctx, "delete postfix queue mail success"))
	return res, nil
}
