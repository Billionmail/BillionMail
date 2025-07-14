package abnormal_recipient

import (
	"billionmail-core/internal/model/entity"
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
