package contact

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"time"

	"billionmail-core/api/contact/v1"
)

func (c *ControllerV1) MergeContactsGroups(ctx context.Context, req *v1.MergeContactsGroupsReq) (res *v1.MergeContactsGroupsRes, err error) {
	res = &v1.MergeContactsGroupsRes{}

	const batchSize = 1000 // Batch size

	err = g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {

		_, err := contact.GetGroup(ctx, req.TargetGroup)
		if err != nil {
			return gerror.New(public.LangCtx(ctx, "Target group not found"))
		}

		for _, sourceId := range req.SourceGroups {
			if _, err := contact.GetGroup(ctx, sourceId); err != nil {
				return gerror.New(public.LangCtx(ctx, "Source group {} not found", sourceId))
			}
		}

		// Batch process data
		offset := 0
		emailStatusMap := make(map[string]int)

		for {
			// 1. Batch get source group contacts
			var contacts []*entity.Contact
			err = g.DB().Model("bm_contacts").
				Where("group_id IN(?)", req.SourceGroups).
				Limit(batchSize).
				Offset(offset).
				Scan(&contacts)

			if err != nil {
				return err
			}

			// If there is no more data, exit the loop
			if len(contacts) == 0 {
				break
			}

			// 2. Process the status of this batch of contacts
			for _, contactInfo := range contacts {
				key := contactInfo.Email
				if existingStatus, ok := emailStatusMap[key]; ok {
					// Only use unsubscribed status when the status is different
					if contactInfo.Active != existingStatus {
						emailStatusMap[key] = 0
					}
				} else {
					emailStatusMap[key] = contactInfo.Active
				}
			}

			offset += batchSize

			// If this batch of data is less than batchSize, it is the last batch
			if len(contacts) < batchSize {
				break
			}
		}

		// 3. Batch check existing contacts in the target group
		var existingEmails []string
		err = g.DB().Model("bm_contacts").
			Fields("email").
			Where("group_id = ?", req.TargetGroup).
			Where("email IN (?)", getMapKeys(emailStatusMap)).
			Scan(&existingEmails)

		if err != nil {
			return err
		}

		// Convert existing emails to map for quick lookup
		existingEmailMap := make(map[string]bool)
		for _, email := range existingEmails {
			existingEmailMap[email] = true
		}

		// 4. Prepare data for insertion
		now := time.Now().Unix()
		var insertData []g.Map

		for email, status := range emailStatusMap {
			// If the email is not in the target group, add it to the insertion list
			if !existingEmailMap[email] {
				insertData = append(insertData, g.Map{
					"email":       email,
					"group_id":    req.TargetGroup,
					"active":      status,
					"create_time": now,
				})
			}
		}

		// 5. Batch insert data
		for i := 0; i < len(insertData); i += batchSize {
			end := i + batchSize
			if end > len(insertData) {
				end = len(insertData)
			}

			_, err = g.DB().Model("bm_contacts").
				Data(insertData[i:end]).
				Insert()

			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to merge contact groups: {}", err.Error())))
		return
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.ContactsGroup,
		Log:  "Contact groups merged successfully",
		Data: req,
	})

	res.SetSuccess(public.LangCtx(ctx, "Contact groups merged successfully"))
	return
}

// getMapKeys Get all keys of map
func getMapKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
