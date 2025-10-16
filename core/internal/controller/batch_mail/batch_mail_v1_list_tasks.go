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

	// Collect all tag IDs and group IDs from all tasks for batch loading
	allTagIds := make(map[int]bool)
	allGroupIds := make(map[int]bool)

	for _, task := range tasks {
		// Collect group IDs
		if task.GroupId > 0 {
			allGroupIds[task.GroupId] = true
		}

		// Collect tag IDs from TagIdsRaw field
		if task.TagIdsRaw != "" {
			tagIds := batch_mail.GetTaskTagIds(task.TagIdsRaw)
			for _, tagId := range tagIds {
				allTagIds[tagId] = true
			}
		}
	}

	// Convert map keys to slices for batch loading
	var tagIdsToFetch []int
	for tagId := range allTagIds {
		tagIdsToFetch = append(tagIdsToFetch, tagId)
	}

	var groupIdsToFetch []int
	for groupId := range allGroupIds {
		groupIdsToFetch = append(groupIdsToFetch, groupId)
	}

	// Batch load all tags
	var allTags []v1.TagInfo
	if len(tagIdsToFetch) > 0 {
		allTags, err = batch_mail.GetTagsByIds(ctx, tagIdsToFetch)
		if err != nil {
			g.Log().Warningf(ctx, "Failed to load tags: %v", err)
			allTags = []v1.TagInfo{}
		}
	}

	// Batch load all group names
	var groupNameMap map[int]string
	if len(groupIdsToFetch) > 0 {
		groupNameMap, err = batch_mail.GetGroupsByIds(ctx, groupIdsToFetch)
		if err != nil {
			g.Log().Warningf(ctx, "Failed to load group names: %v", err)
			groupNameMap = make(map[int]string)
		}
	} else {
		groupNameMap = make(map[int]string)
	}

	// Create tag lookup map
	tagMap := make(map[int]v1.TagInfo)
	for _, tag := range allTags {
		tagMap[tag.Id] = tag
	}

	for i, task := range tasks {
		detail := &v1.TaskDetail{
			EmailTask: *task,
		}

		// Set group name
		if groupName, exists := groupNameMap[task.GroupId]; exists {
			detail.GroupName = groupName
		}

		// Load and populate tags for this task
		if task.TagIdsRaw != "" {
			tagIds := batch_mail.GetTaskTagIds(task.TagIdsRaw)
			detail.Tags = make([]v1.TagInfo, 0, len(tagIds))
			for _, tagId := range tagIds {
				if tag, exists := tagMap[tagId]; exists {
					detail.Tags = append(detail.Tags, tag)
				}
			}
		} else {
			detail.Tags = []v1.TagInfo{}
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
			if detail.Progress > 100 || detail.Progress >= 98 {
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
