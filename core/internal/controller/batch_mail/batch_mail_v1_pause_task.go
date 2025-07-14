package batch_mail

import (
	"billionmail-core/api/batch_mail/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/batch_mail"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
)

func (c *ControllerV1) PauseTask(ctx context.Context, req *v1.PauseTaskReq) (res *v1.PauseTaskRes, err error) {
	res = &v1.PauseTaskRes{}

	// validate task info
	taskInfo, err := batch_mail.GetTaskInfo(ctx, req.TaskId)
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get task information: {}", err.Error())))
		return
	}

	if taskInfo == nil || taskInfo.Id == 0 {
		res.Code = 404
		res.SetError(gerror.New(public.LangCtx(ctx, "Task not found: {}", req.TaskId)))
		return
	}

	// check task status, only running tasks can be paused
	if taskInfo.TaskProcess != 1 { // 1 represents running
		res.Code = 400

		var statusText string
		switch taskInfo.TaskProcess {
		case 0:
			statusText = "not started"
		case 2:
			statusText = "already completed"
		default:
			statusText = "in unknown state"
		}

		res.SetError(gerror.New(public.LangCtx(ctx, "Cannot pause task because it is {}", statusText)))
		return
	}

	// if task is already paused, return success directly
	if taskInfo.Pause == 1 {
		res.SetSuccess(public.LangCtx(ctx, "Task is already paused"))
		return
	}

	// get task executor
	executor := batch_mail.GetTaskExecutor(req.TaskId)
	if executor == nil {
		// no active executor, update database status directly
		if err := batch_mail.UpdateTaskPauseStatus(ctx, req.TaskId, true); err != nil {
			res.Code = 500
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to pause task: {}", err.Error())))
			return nil, err
		}
	} else {
		// pause task through executor
		if err := executor.PauseTask(req.TaskId); err != nil {
			res.Code = 500
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to pause task: {}", err.Error())))
			return nil, err
		}
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Task,
		Log:  "Pause Task :" + taskInfo.Subject + " successfully",
		Data: taskInfo,
	})
	res.SetSuccess(public.LangCtx(ctx, "Task paused successfully"))
	return
}
