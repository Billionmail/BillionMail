package abnormal_recipient

import (
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/maillog_stat"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"time"
)

func GetListWithPage(ctx context.Context, page, pageSize int, keyword string, addType int) (total int, list []*entity.AbnormalRecipient, err error) {

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}

	model := g.DB().Model("abnormal_recipient").Safe()

	if keyword != "" {
		model = model.WhereLike("recipient", "%"+keyword+"%")
	}
	if addType > 0 {
		model = model.Where("add_type", addType)
	}

	total, err = model.Count()
	if err != nil {
		return 0, nil, fmt.Errorf("Failed to get the total number of exception recipients: %w", err)
	}

	list = make([]*entity.AbnormalRecipient, 0)
	err = model.Page(page, pageSize).
		Order("create_time DESC").
		Scan(&list)

	if err != nil {
		return 0, nil, fmt.Errorf("Failed to get the exception recipient list: %w", err)
	}

	return total, list, nil
}

func Add(ctx context.Context, recipient string) error {

	now := time.Now().Unix()
	_, err := g.DB().Model("abnormal_recipient").
		Data(g.Map{
			"recipient":   recipient,
			"count":       3,
			"add_type":    1,
			"description": "Manually added",
			"create_time": now,
		}).
		InsertIgnore()

	if err != nil {
		return fmt.Errorf("Failed to add exception recipient: %w", err)
	}

	return nil
}

func Delete(ctx context.Context, id int) error {

	_, err := g.DB().Model("abnormal_recipient").
		Where("id", id).
		Delete()

	if err != nil {
		return fmt.Errorf("Failed to remove exception recipient: %w", err)
	}

	return nil
}

func GetAbnormalRecipient(ctx context.Context, id int) (*entity.AbnormalRecipient, error) {
	var recipient entity.AbnormalRecipient
	err := g.DB().Model("abnormal_recipient").Where("id", id).Scan(&recipient)
	if err != nil {
		return nil, fmt.Errorf("Failed to get exception recipient: %w", err)
	}
	return &recipient, nil
}

func BatchUpsertAbnormalRecipients(ctx context.Context, recipients []string, addType int, description string) error {
	now := time.Now().Unix()

	if len(recipients) == 0 {
		return nil
	}

	var existList []entity.AbnormalRecipient
	err := g.DB().Model("abnormal_recipient").WhereIn("recipient", recipients).Scan(&existList)
	if err != nil {
		return fmt.Errorf("Failed to query existing abnormal recipients: %w", err)
	}
	existMap := make(map[string]*entity.AbnormalRecipient)
	for _, r := range existList {
		existMap[r.Recipient] = &r
	}
	// 1. Update the existing one count+1
	for _, r := range existList {
		_, err := g.DB().Model("abnormal_recipient").Where("id", r.Id).Data(g.Map{
			"count":       r.Count + 1,
			"description": description,
			"add_type":    addType,
		}).Update()
		if err != nil {

			return fmt.Errorf("Failed to update abnormal recipient: %w", err)
		}

	}
	// 2. Inserting something that doesn't exist
	var insertList []g.Map
	for _, recipient := range recipients {
		if _, ok := existMap[recipient]; !ok {
			insertList = append(insertList, g.Map{
				"recipient":   recipient,
				"count":       1,
				"add_type":    addType,
				"description": description,
				"create_time": now,
			})
		}
	}
	if len(insertList) > 0 {

		_, err := g.DB().Model("abnormal_recipient").Data(insertList).InsertIgnore()
		if err != nil {

			return fmt.Errorf("Failed to insert abnormal recipients: %w", err)
		}
	}

	return nil
}

func AbnormalRecipientAutoStat(ctx context.Context) {

	var abnormalSwitch string
	val, err := g.DB().Model("bm_options").Where("name", "abnormal_mail_check_switch").Value("value")
	if err == nil && val != nil && val.String() != "" {
		abnormalSwitch = val.String()
	} else {
		abnormalSwitch = "1"
	}
	if abnormalSwitch != "1" {
		return
	}

	lastTime := getLastStatTime(ctx)
	now := time.Now().Unix()

	overview := maillog_stat.NewOverview()
	failedList := overview.FailedList(0, "", lastTime, now)

	recipientSet := make(map[string]struct{})
	for _, item := range failedList {
		if recipient, ok := item["recipient"].(string); ok && recipient != "" {
			recipientSet[recipient] = struct{}{}
		}
	}
	var recipients []string
	for r := range recipientSet {
		recipients = append(recipients, r)
	}

	if len(recipients) > 0 {
		_ = BatchUpsertAbnormalRecipients(ctx, recipients, 2, "Automatic statistics")
	}

	setLastStatTime(ctx, now)

}

func getLastStatTime(ctx context.Context) int64 {
	var lastTime int64
	val, err := g.DB().Model("bm_options").Where("name", "abnormal_recipient_last_time").Value("value")
	if err == nil && val != nil && val.String() != "" {
		lastTime = val.Int64()

	} else {
		lastTime = time.Now().Add(-30 * time.Minute).Unix()

	}
	return lastTime
}

func setLastStatTime(ctx context.Context, t int64) {
	_, err := g.DB().Model("bm_options").
		Data(g.Map{
			"name":  "abnormal_recipient_last_time",
			"value": t,
		}).
		OnConflict("name").
		Save()
	if err != nil {
		g.Log().Debugf(ctx, "[abnormal Recipient] Error occurred in the last statistics time recording: %v", err)
	}
}
