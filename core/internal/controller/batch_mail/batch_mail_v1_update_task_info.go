package batch_mail

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/batch_mail"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/batch_mail/v1"
)

func (c *ControllerV1) UpdateTaskInfo(ctx context.Context, req *v1.UpdateTaskInfoReq) (res *v1.UpdateTaskInfoRes, err error) {

	res = &v1.UpdateTaskInfoRes{}

	var task struct {
		Id          int `json:"id"`
		TaskProcess int `json:"task_process"`
		Pause       int `json:"pause"`
	}

	err = g.DB().Model("email_tasks").
		Fields("id, task_process, pause").
		Where("id", req.TaskId).
		Scan(&task)

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Query task failed: {}", err.Error())))
		return nil, err
	}

	if task.Id == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "The task does not exist.")))
		return
	}

	executor := batch_mail.GetTaskExecutor(req.TaskId)
	if executor != nil && executor.IsRunning() && task.Pause == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "The task is currently running. Please pause the task first.")))
		return
	}
	updateData := map[string]interface{}{}
	// 0 or 1 fields
	if req.Unsubscribe == 0 || req.Unsubscribe == 1 {
		updateData["unsubscribe"] = req.Unsubscribe
	}
	if req.Warmup == 0 || req.Warmup == 1 {
		updateData["warmup"] = req.Warmup
	}

	if req.Addresser != "" {
		updateData["addresser"] = req.Addresser
	}
	if req.Subject != "" {
		updateData["subject"] = req.Subject
	}
	if req.FullName != "" {
		updateData["full_name"] = req.FullName
	}

	if req.Remark != "" {
		updateData["remark"] = req.Remark
	}
	if req.TemplateId > 0 {
		updateData["template_id"] = req.TemplateId
	}
	if req.Threads > 0 {
		updateData["threads"] = req.Threads
	}
	if req.StartTime > 0 {
		updateData["start_time"] = req.StartTime
	}

	if len(req.TagIds) > 0 {
		updateData["tag_ids"] = req.TagIds
	}
	if req.TagLogic == "AND" || req.TagLogic == "OR" {
		updateData["tag_logic"] = req.TagLogic
	}
	if len(updateData) == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "No valid update fields")))
		return
	}

	_, err = g.DB().Model("email_tasks").
		Where("id", req.TaskId).
		Data(updateData).
		Update()

	if err != nil {

		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to update task information : {}", err.Error())))
		return nil, err
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Task,
		Log:  "Update Task Info :" + updateData["subject"].(string) + " successfully",
		Data: updateData,
	})

	res.SetSuccess(public.LangCtx(ctx, "Task update successful"))
	return
}
