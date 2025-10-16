package contact

import (
	"billionmail-core/internal/service/public"
	"context"
	"database/sql"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"strconv"
	"strings"
	"time"

	"billionmail-core/api/contact/v1"
)

func (c *ControllerV1) ListContactsNDP(ctx context.Context, req *v1.ListContactsNDPReq) (res *v1.ListContactsNDPRes, err error) {
	res = &v1.ListContactsNDPRes{}

	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 1000 {
		req.PageSize = 20
	}

	if req.SortBy == "" {
		req.SortBy = "create_time"
	}
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}

	model := g.DB().Model("bm_contacts c").Safe()

	if req.GroupId > 0 {
		model = model.Where("c.group_id", req.GroupId)
	}
	if req.Keyword != "" {
		model = model.WhereLike("c.email", "%"+req.Keyword+"%")
	}
	if req.Active != -1 {
		model = model.Where("c.active", req.Active)
	}

	if req.Tags != "" && req.Tags != "-1" {
		tagIds := strings.Split(req.Tags, ",")
		var validTagIds []int
		for _, tagIdStr := range tagIds {
			tagIdStr = strings.TrimSpace(tagIdStr)
			if tagIdStr != "" {
				if tagId, err := strconv.Atoi(tagIdStr); err == nil && tagId > 0 {
					validTagIds = append(validTagIds, tagId)
				}
			}
		}

		if len(validTagIds) > 0 {

			model = model.InnerJoin("bm_contact_tags ct", "c.id = ct.contact_id").
				WhereIn("ct.tag_id", validTagIds)
		}
	}

	if req.LastActiveStatus != -1 && req.TimeInterval > 0 {
		now := time.Now()
		var timeCondition time.Time

		switch req.TimeInterval {
		case 7:
			timeCondition = now.AddDate(0, 0, -7)
		case 30:
			timeCondition = now.AddDate(0, -1, 0)
		case 90:
			timeCondition = now.AddDate(0, -3, 0)
		case 180:
			timeCondition = now.AddDate(0, -6, 0)
		case 365:
			timeCondition = now.AddDate(-1, 0, 0)
		}

		timeConditionUnix := timeCondition.Unix()

		if req.LastActiveStatus == 1 {

			model = model.Where("c.last_active_at >= ?", timeConditionUnix)
		} else if req.LastActiveStatus == 0 {

			model = model.Where("c.last_active_at < ? OR c.last_active_at IS NULL OR c.last_active_at = 0", timeConditionUnix)
		}
	}

	if req.Tags != "" && req.Tags != "-1" {
		model = model.Group("c.id")
	}

	countModel := model.Clone()
	total, err := countModel.Count()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get contacts count: {}", err.Error())))
		return
	}

	var orderBy string
	switch req.SortBy {
	case "create_time":
		orderBy = "c.create_time"
	case "last_active_at":
		orderBy = "c.last_active_at"
	default:
		orderBy = "c.create_time"
	}

	if req.SortOrder == "asc" {
		orderBy += " ASC"
	} else {
		orderBy += " DESC"
	}

	orderBy += ", c.id DESC"

	var contacts []*v1.Contact
	queryModel := model.Fields("c.*, cg.name as group_name").
		LeftJoin("bm_contact_groups cg", "c.group_id = cg.id")

	if req.Tags != "" && req.Tags != "-1" {
		queryModel = queryModel.Group("c.id, cg.name")
	}

	err = queryModel.Order(orderBy).
		Page(req.Page, req.PageSize).
		Scan(&contacts)

	if err != nil && err != sql.ErrNoRows {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get contacts list: {}", err.Error())))
		return
	}

	if len(contacts) > 0 {
		err = c.attachContactTags(ctx, contacts)
		if err != nil {
			g.Log().Warning(ctx, "Failed to attach tags to contacts: %v", err)
		}
	}

	res.Data.Total = total
	res.Data.List = contacts
	res.SetSuccess(public.LangCtx(ctx, "Get contacts list successfully"))
	return
}

func (c *ControllerV1) attachContactTags(ctx context.Context, contacts []*v1.Contact) error {
	if len(contacts) == 0 {
		return nil
	}

	contactIds := make([]int, len(contacts))
	contactMap := make(map[int]*v1.Contact)
	for i, contact := range contacts {
		contactIds[i] = contact.Id
		contactMap[contact.Id] = contact

		contact.Tags = []v1.TagInfo{}
	}

	var contactTags []struct {
		ContactId  int    `json:"contact_id"`
		TagId      int    `json:"tag_id"`
		TagName    string `json:"tag_name"`
		CreateTime int    `json:"create_time"`
	}

	err := g.DB().Model("bm_contact_tags ct").
		LeftJoin("bm_tags t", "ct.tag_id = t.id").
		Fields("ct.contact_id, t.id as tag_id, t.name as tag_name, ct.create_time").
		WhereIn("ct.contact_id", contactIds).
		Order("ct.create_time DESC").
		Scan(&contactTags)
	if err != nil {
		return err
	}

	for _, contactTag := range contactTags {
		if contact, exists := contactMap[contactTag.ContactId]; exists {
			tagInfo := v1.TagInfo{
				Id:         contactTag.TagId,
				Name:       contactTag.TagName,
				CreateTime: contactTag.CreateTime,
			}
			contact.Tags = append(contact.Tags, tagInfo)
		}
	}

	return nil
}
