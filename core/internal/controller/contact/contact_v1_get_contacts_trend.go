package contact

import (
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"strconv"
	"strings"
	"time"

	"billionmail-core/api/contact/v1"
)

func (c *ControllerV1) GetContactsTrend(ctx context.Context, req *v1.GetContactsTrendReq) (res *v1.GetContactsTrendRes, err error) {
	res = &v1.GetContactsTrendRes{}

	var timeGranularity string
	var startTime, endTime time.Time
	now := time.Now()

	switch req.TimeInterval {
	case 7, 30, 90, 180:
		timeGranularity = "daily"
		startTime = now.AddDate(0, 0, -req.TimeInterval).Truncate(24 * time.Hour)
		endTime = now.Truncate(24 * time.Hour).Add(24*time.Hour - time.Second)
	case 365, 0:
		timeGranularity = "monthly"
		startTime = now.AddDate(0, -11, 0).Truncate(24 * time.Hour)
		endTime = now.Truncate(24 * time.Hour).Add(24*time.Hour - time.Second)
	default:
		timeGranularity = "monthly"
		startTime = now.AddDate(0, -11, 0).Truncate(24 * time.Hour)
		endTime = now.Truncate(24 * time.Hour).Add(24*time.Hour - time.Second)
	}

	g.Log().Infof(ctx, "GetContactsTrend: TimeInterval=%d, Granularity=%s, StartTime=%s, EndTime=%s, Active=%d, LastActiveStatus=%d",
		req.TimeInterval, timeGranularity, startTime.Format("2006-01-02 15:04:05"), endTime.Format("2006-01-02 15:04:05"), req.Active, req.LastActiveStatus)

	baseModel := g.DB().Model("bm_contacts c").Safe()

	if req.GroupId > 0 {
		baseModel = baseModel.Where("c.group_id", req.GroupId)
	}

	if req.Active != -1 {
		baseModel = baseModel.Where("c.active", req.Active)
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
			baseModel = baseModel.InnerJoin("bm_contact_tags ct", "c.id = ct.contact_id").
				WhereIn("ct.tag_id", validTagIds)
		}
	}

	if req.LastActiveStatus != -1 && req.TimeInterval > 0 {
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

			baseModel = baseModel.Where("c.last_active_at >= ?", timeConditionUnix)
		} else if req.LastActiveStatus == 0 {

			baseModel = baseModel.Where("c.last_active_at < ? OR c.last_active_at IS NULL OR c.last_active_at = 0", timeConditionUnix)
		}

		g.Log().Infof(ctx, "Active status filter applied: LastActiveStatus=%d, TimeCondition=%s",
			req.LastActiveStatus, timeCondition.Format("2006-01-02 15:04:05"))
	}

	if req.LastActiveStatus == -1 {

		startTimeUnix := startTime.Unix()
		endTimeUnix := endTime.Unix()
		baseModel = baseModel.WhereBetween("c.create_time", startTimeUnix, endTimeUnix)
	}

	res.Data.TimeGranularity = timeGranularity

	if timeGranularity == "daily" {

		err = c.getDailyTrend(ctx, baseModel, startTime, endTime, req.Active, req.LastActiveStatus, res)
	} else {

		err = c.getMonthlyTrend(ctx, baseModel, startTime, endTime, req.Active, req.LastActiveStatus, res)
	}

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get contacts trend: {}", err.Error())))
		return
	}

	res.SetSuccess(public.LangCtx(ctx, "Get contacts trend successfully"))
	return
}

func (c *ControllerV1) getDailyTrend(ctx context.Context, baseModel *gdb.Model, startTime, endTime time.Time, activeFilter, lastActiveStatus int, res *v1.GetContactsTrendRes) error {

	data, err := c.getDailyTrendByStatus(ctx, baseModel, activeFilter, lastActiveStatus)
	if err != nil {
		return err
	}

	res.Data.DailyData = c.fillDailyTrendData(data, startTime, endTime)
	return nil
}

func (c *ControllerV1) getMonthlyTrend(ctx context.Context, baseModel *gdb.Model, startTime, endTime time.Time, activeFilter, lastActiveStatus int, res *v1.GetContactsTrendRes) error {

	data, err := c.getMonthlyTrendByStatus(ctx, baseModel, activeFilter, lastActiveStatus)
	if err != nil {
		return err
	}

	res.Data.MonthlyData = c.fillMonthlyTrendData(data, startTime, endTime)
	return nil
}

func (c *ControllerV1) getDailyTrendByStatus(ctx context.Context, model *gdb.Model, active, lastActiveStatus int) ([]struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}, error) {
	var data []struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}

	var timeField string
	if lastActiveStatus != -1 {

		timeField = "c.last_active_at"
	} else {

		timeField = "c.create_time"
	}

	queryModel := model.Clone()
	if active != -1 {
		queryModel = queryModel.Where("c.active", active)
	}

	err := queryModel.
		Fields("TO_CHAR(TO_TIMESTAMP(" + timeField + "), 'YYYY-MM-DD') as date, COUNT(DISTINCT c.id) as count").
		Group("TO_CHAR(TO_TIMESTAMP(" + timeField + "), 'YYYY-MM-DD')").
		Order("date ASC").
		Scan(&data)

	if err != nil {
		g.Log().Error(ctx, "Failed to get daily trend data for active=%d, lastActiveStatus=%d: %v", active, lastActiveStatus, err)
		return nil, err
	}

	g.Log().Debug(ctx, "getDailyTrendByStatus: active=%d, lastActiveStatus=%d, timeField=%s, results=%d",
		active, lastActiveStatus, timeField, len(data))

	return data, nil
}

func (c *ControllerV1) getMonthlyTrendByStatus(ctx context.Context, model *gdb.Model, active, lastActiveStatus int) ([]struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}, error) {
	var data []struct {
		Month string `json:"month"`
		Count int    `json:"count"`
	}

	var timeField string
	if lastActiveStatus != -1 {

		timeField = "c.last_active_at"
	} else {

		timeField = "c.create_time"
	}

	queryModel := model.Clone()
	if active != -1 {
		queryModel = queryModel.Where("c.active", active)
	}

	err := queryModel.
		Fields("TO_CHAR(TO_TIMESTAMP(" + timeField + "), 'YYYY-MM') as month, COUNT(DISTINCT c.id) as count").
		Group("TO_CHAR(TO_TIMESTAMP(" + timeField + "), 'YYYY-MM')").
		Order("month ASC").
		Scan(&data)

	if err != nil {
		g.Log().Error(ctx, "Failed to get monthly trend data for active=%d, lastActiveStatus=%d: %v", active, lastActiveStatus, err)
		return nil, err
	}

	g.Log().Debug(ctx, "getMonthlyTrendByStatus: active=%d, lastActiveStatus=%d, timeField=%s, results=%d",
		active, lastActiveStatus, timeField, len(data))

	return data, nil
}

func (c *ControllerV1) fillDailyTrendData(data []struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}, startTime, endTime time.Time) []*v1.DailyCount {

	dataMap := make(map[string]int)
	for _, item := range data {
		dataMap[item.Date] = item.Count
	}

	var result []*v1.DailyCount

	for d := startTime; d.Before(endTime) || d.Equal(endTime); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")

		count := 0
		if c, exists := dataMap[dateStr]; exists {
			count = c
		}

		result = append(result, &v1.DailyCount{
			Date:  dateStr,
			Count: count,
		})
	}

	return result
}

func (c *ControllerV1) fillMonthlyTrendData(data []struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}, startTime, endTime time.Time) []*v1.MonthlyCount {

	dataMap := make(map[string]int)
	for _, item := range data {
		dataMap[item.Month] = item.Count
	}

	var result []*v1.MonthlyCount

	for d := startTime; d.Before(endTime) || d.Equal(endTime); d = d.AddDate(0, 1, 0) {
		monthStr := d.Format("2006-01")

		count := 0
		if c, exists := dataMap[monthStr]; exists {
			count = c
		}

		result = append(result, &v1.MonthlyCount{
			Date: monthStr,
			Count: count,
		})
	}

	return result
}
