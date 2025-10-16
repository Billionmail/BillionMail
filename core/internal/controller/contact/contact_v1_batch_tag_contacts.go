package contact

import (
	"context"
	"database/sql"
	"time"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/contact/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
)

func (c *ControllerV1) BatchTagContacts(ctx context.Context, req *v1.BatchTagContactsReq) (res *v1.BatchTagContactsRes, err error) {
	res = &v1.BatchTagContactsRes{}

	if len(req.Ids) == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "No contact IDs provided")))
		return
	}

	if len(req.TagIds) == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "No tag IDs provided")))
		return
	}

	g.Log().Infof(ctx, "BatchTagContacts: Processing %d contacts with %d tags, action: %d",
		len(req.Ids), len(req.TagIds), req.Action)

	var processedCount, skippedCount, errorCount int


	err = g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		if req.Action == 1 {

			processedCount, skippedCount, errorCount, err = c.batchAddTagsToContacts(ctx, tx, req.Ids, req.TagIds)
		} else {

			processedCount, skippedCount, errorCount, err = c.batchRemoveTagsFromContacts(ctx, tx, req.Ids, req.TagIds)
		}
		return err
	})

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to process batch tag operation")))
		return
	}


	operation := "Add tags"
	if req.Action == 2 {
		operation = "Remove tags"
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Tag,
		Log: operation + " for " + g.NewVar(processedCount).String() + " contacts successfully",
		Data: map[string]interface{}{
			"tag_ids":        req.TagIds,
			"contact_ids":    req.Ids,
			"operation":      operation,
			"total_contacts": len(req.Ids),
			"processed":      processedCount,
			"skipped":        skippedCount,
			"errors":         errorCount,
		},
	})


	var successMsg string
	if req.Action == 1 {
		successMsg = public.LangCtx(ctx, "Successfully added tags to {} contacts", processedCount)
	} else {
		successMsg = public.LangCtx(ctx, "Successfully removed tags from {} contacts", processedCount)
	}

	if skippedCount > 0 || errorCount > 0 {
		successMsg += public.LangCtx(ctx, " ({} skipped, {} errors)", skippedCount, errorCount)
	}

	res.SetSuccess(successMsg)
	return
}


func (c *ControllerV1) batchAddTagsToContacts(ctx context.Context, tx gdb.TX, contactIds []int, tagIds []int) (processed, skipped, errors int, err error) {
	const batchSize = 500
	now := time.Now().Unix()


	var existingContacts []struct {
		Id      int `json:"id"`
		GroupId int `json:"group_id"`
	}
	err = tx.Model("bm_contacts").
		Fields("id, group_id").
		WhereIn("id", contactIds).
		Scan(&existingContacts)
	if err != nil && err != sql.ErrNoRows  {
		g.Log().Error(ctx, "Failed to query existing contacts: %v", err)
		return 0, 0, len(contactIds), err
	}

	if len(existingContacts) == 0 {
		return 0, len(contactIds), 0, nil
	}


	validContactIds := make([]int, len(existingContacts))
	contactGroupMap := make(map[int]int) // contact_id -> group_id
	for i, contact := range existingContacts {
		validContactIds[i] = contact.Id
		contactGroupMap[contact.Id] = contact.GroupId
	}


	var existingTags []struct {
		Id      int `json:"id"`
		GroupId int `json:"group_id"`
		Name    string `json:"name"`
	}
	err = tx.Model("bm_tags").
		Fields("id, group_id, name").
		WhereIn("id", tagIds).
		Scan(&existingTags)
	if err != nil && err != sql.ErrNoRows {
		g.Log().Error(ctx, "Failed to query existing tags: %v", err)
		return 0, 0, len(contactIds), err
	}

	if len(existingTags) == 0 {
		return 0, len(contactIds), 0, nil
	}

	validTagIds := make([]int, len(existingTags))
	tagGroupMap := make(map[int]int) // tag_id -> group_id
	for i, tag := range existingTags {
		validTagIds[i] = tag.Id
		tagGroupMap[tag.Id] = tag.GroupId
	}


	var existingTagRelations []struct {
		ContactId int `json:"contact_id"`
		TagId     int `json:"tag_id"`
	}
	err = tx.Model("bm_contact_tags").
		Fields("contact_id, tag_id").
		WhereIn("contact_id", validContactIds).
		WhereIn("tag_id", validTagIds).
		Scan(&existingTagRelations)
	if err != nil && err != sql.ErrNoRows {
		g.Log().Error(ctx, "Failed to query existing tag relations: %v", err)
		return 0, 0, len(contactIds), err
	}


	existingRelationMap := make(map[string]bool)
	for _, relation := range existingTagRelations {
		key := g.NewVar(relation.ContactId).String() + "_" + g.NewVar(relation.TagId).String()
		existingRelationMap[key] = true
	}


	var currentBatch []g.Map
	batchCount := 0

	for _, contactId := range validContactIds {
		contactGroupId := contactGroupMap[contactId]

		for _, tagId := range validTagIds {
			tagGroupId := tagGroupMap[tagId]


			if contactGroupId != tagGroupId {
				skipped++
				continue
			}


			key := g.NewVar(contactId).String() + "_" + g.NewVar(tagId).String()
			if existingRelationMap[key] {
				skipped++
				continue
			}

			currentBatch = append(currentBatch, g.Map{
				"contact_id":  contactId,
				"tag_id":      tagId,
				"create_time": now,
			})


			if len(currentBatch) >= batchSize {
				_, err = tx.Model("bm_contact_tags").InsertIgnore(currentBatch)
				if err != nil {
					g.Log().Error(ctx, "Failed to insert contact tags batch: %v", err)
					errors += len(currentBatch)
				} else {
					processed += len(currentBatch)
				}
				currentBatch = nil
				batchCount++
			}
		}
	}


	if len(currentBatch) > 0 {
		_, err = tx.Model("bm_contact_tags").InsertIgnore(currentBatch)
		if err != nil {
			g.Log().Error(ctx, "Failed to insert final contact tags batch: %v", err)
			errors += len(currentBatch)
		} else {
			processed += len(currentBatch)
		}
	}


	return processed, skipped, errors, nil
}


func (c *ControllerV1) batchRemoveTagsFromContacts(ctx context.Context, tx gdb.TX, contactIds []int, tagIds []int) (processed, skipped, errors int, err error) {
	const batchSize = 500


	var existingContacts []struct {
		Id int `json:"id"`
	}
	err = tx.Model("bm_contacts").
		Fields("id").
		WhereIn("id", contactIds).
		Scan(&existingContacts)
	if err != nil && err != sql.ErrNoRows {
		g.Log().Error(ctx, "Failed to query existing contacts: %v", err)
		return 0, 0, len(contactIds), err
	}

	if len(existingContacts) == 0 {
		return 0, len(contactIds), 0, nil
	}

	validContactIds := make([]int, len(existingContacts))
	for i, contact := range existingContacts {
		validContactIds[i] = contact.Id
	}


	var existingTags []struct {
		Id int `json:"id"`
	}
	err = tx.Model("bm_tags").
		Fields("id").
		WhereIn("id", tagIds).
		Scan(&existingTags)
	if err != nil && err != sql.ErrNoRows {
		g.Log().Error(ctx, "Failed to query existing tags: %v", err)
		return 0, 0, len(contactIds), err
	}

	if len(existingTags) == 0 {
		return 0, len(contactIds), 0, nil
	}

	validTagIds := make([]int, len(existingTags))
	for i, tag := range existingTags {
		validTagIds[i] = tag.Id
	}


	for i := 0; i < len(validContactIds); i += batchSize {
		end := i + batchSize
		if end > len(validContactIds) {
			end = len(validContactIds)
		}

		currentContactBatch := validContactIds[i:end]


		result, err := tx.Model("bm_contact_tags").
			WhereIn("contact_id", currentContactBatch).
			WhereIn("tag_id", validTagIds).
			Delete()

		if err != nil {
			g.Log().Error(ctx, "Failed to delete contact tags batch: %v", err)
			errors += len(currentContactBatch) * len(validTagIds)
			continue
		}

		rowsAffected, _ := result.RowsAffected()
		processed += int(rowsAffected)
	}


	totalExpected := len(validContactIds) * len(validTagIds)
	skipped = totalExpected - processed - errors


	return processed, skipped, errors, nil
}
