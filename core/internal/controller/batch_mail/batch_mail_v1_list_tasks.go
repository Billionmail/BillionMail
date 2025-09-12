package batch_mail

import (
	"billionmail-core/api/batch_mail/v1"
	"billionmail-core/internal/service/batch_mail"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) ListTasks(ctx context.Context, req *v1.ListTasksReq) (res *v1.ListTasksRes, err error) {

	res = &v1.ListTasksRes{}

	total, tasks, err := batch_mail.GetTasksWithPage(ctx, req.Page, req.PageSize, req.Keyword, req.Status)
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get task list {}", err.Error())))
		return
	}

	task_list := make([]*v1.TaskDetail, len(tasks))
	for i, task := range tasks {
		detail := &v1.TaskDetail{
			EmailTask: *task,
		}

		detail.SentCount = task.SendsCount
		detail.SuccessCount = task.DeliveredCount
		detail.Deferred = task.DeferredCount
		detail.ErrorCount = task.BouncedCount + task.DeferredCount

		sentCount := detail.SentCount

		if task.RecipientCount <= 0 {

			actualCount, err := batch_mail.GetActualRecipientCount(ctx, task.Id)
			if err == nil && actualCount > 0 {

				_ = batch_mail.UpdateRecipientCount(ctx, task.Id, actualCount)
				detail.RecipientCount = actualCount
				task.RecipientCount = actualCount
			}
		}

		// Now calculate unsent_count with the corrected recipient_count
		if task.RecipientCount >= sentCount {
			detail.UnsentCount = task.RecipientCount - sentCount
		} else {
			// If still inconsistent, set unsent count to 0
			detail.UnsentCount = 0
			g.Log().Infof(ctx, "Task %d has inconsistent data: recipient_count(%d) < sent_count(%d)",
				task.Id, task.RecipientCount, sentCount)
		}

		if task.RecipientCount > 0 {
			detail.Progress = int(float64(sentCount) / float64(task.RecipientCount) * 100)
			if detail.Progress > 100 || detail.Progress == 99 {
				detail.Progress = 100
			}
		} else {
			// Default progress for tasks with no recipients
			detail.Progress = 0
		}

		task_list[i] = detail
	}

	res.Data.Total = total
	res.Data.List = task_list
	res.SetSuccess(public.LangCtx(ctx, "Task list retrieved successfully"))
	return
}
