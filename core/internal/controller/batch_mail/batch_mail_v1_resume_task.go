package batch_mail

import (
	"billionmail-core/api/batch_mail/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/batch_mail"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) ResumeTask(ctx context.Context, req *v1.ResumeTaskReq) (res *v1.ResumeTaskRes, err error) {
	res = &v1.ResumeTaskRes{}

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

	// check task status, only paused or running tasks can be resumed
	if taskInfo.TaskProcess != 1 && taskInfo.TaskProcess != 3 { // 1=running, 3=paused
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

		res.SetError(gerror.New(public.LangCtx(ctx, "Cannot resume task because it is {}", statusText)))
		return
	}

	// if task is not paused, return success directly
	if taskInfo.Pause == 0 {
		res.SetSuccess(public.LangCtx(ctx, "Task is already running"))
		return
	}

	// get task executor
	executor := batch_mail.GetTaskExecutor(req.TaskId)
	if executor == nil {
		// no active executor, update database status directly
		if err := batch_mail.UpdateTaskPauseStatus(ctx, req.TaskId, false); err != nil {
			res.Code = 500
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to resume task: {}", err.Error())))
			return nil, err
		}

		// trigger new task processing
		go func() {
			// create new executor and process task
			newExecutor := batch_mail.GetOrCreateTaskExecutor(context.Background(), req.TaskId)
			batch_mail.RegisterTaskExecutor(req.TaskId, newExecutor)
			if err := newExecutor.ProcessTask(context.Background()); err != nil {
				g.Log().Error(context.Background(), "Failed to process resumed task: %v", err)
			}
		}()
	} else {
		// resume task through executor
		if err := executor.ResumeTask(req.TaskId); err != nil {
			res.Code = 500
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to resume task: {}", err.Error())))
			return nil, err
		}
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Task,
		Log:  "Resumed Task :" + taskInfo.Subject + " successfully",
		Data: taskInfo,
	})

	res.SetSuccess(public.LangCtx(ctx, "Task resumed successfully"))
	return
}
