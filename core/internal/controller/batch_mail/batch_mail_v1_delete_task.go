package batch_mail

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/batch_mail"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/batch_mail/v1"
)

func (c *ControllerV1) DeleteTask(ctx context.Context, req *v1.DeleteTaskReq) (res *v1.DeleteTaskRes, err error) {
	res = &v1.DeleteTaskRes{}

	task, _ := batch_mail.GetTaskInfo(ctx, req.Id)
	err = batch_mail.DeleteTask(ctx, req.Id)
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to delete task {}", err.Error())))
		return
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Task,
		Log:  "Delete task :" + task.Subject + " successfully",
		Data: task,
	})

	res.SetSuccess(public.LangCtx(ctx, "Task deleted successfully"))
	return
}
