package contact

import (
	"billionmail-core/internal/service/contact"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"time"

	"billionmail-core/api/contact/v1"
)

func (c *ControllerV1) GetContactsTrend(ctx context.Context, req *v1.GetContactsTrendReq) (res *v1.GetContactsTrendRes, err error) {
	res = &v1.GetContactsTrendRes{}

	// Get trend data for the last 12 months
	now := time.Now()
	trends, err := contact.GetContactsTrend(ctx, now.AddDate(0, -11, 0), now, req.GroupId)
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get contacts trend: {}", err.Error())))
		return
	}

	subscribeTrend := make([]*v1.MonthlyCount, 0)
	unsubscribeTrend := make([]*v1.MonthlyCount, 0)

	// Iterate through the last 12 months
	for i := 11; i >= 0; i-- {
		currentMonth := now.AddDate(0, -i, 0)
		monthStr := currentMonth.Format("2006-01")

		// Check if the month exists in the trends data
		found := false
		for _, trend := range trends {
			if trend.Month == monthStr {
				subscribeTrend = append(subscribeTrend, &v1.MonthlyCount{
					Month: monthStr,
					Count: trend.SubscribeCount,
				})
				unsubscribeTrend = append(unsubscribeTrend, &v1.MonthlyCount{
					Month: monthStr,
					Count: trend.UnsubscribeCount,
				})
				found = true
				break
			}
		}

		// No data, Add 0
		if !found {
			subscribeTrend = append(subscribeTrend, &v1.MonthlyCount{
				Month: monthStr,
				Count: 0,
			})
			unsubscribeTrend = append(unsubscribeTrend, &v1.MonthlyCount{
				Month: monthStr,
				Count: 0,
			})
		}
	}

	res.Data.Subscribe = subscribeTrend
	res.Data.Unsubscribe = unsubscribeTrend
	res.SetSuccess(public.LangCtx(ctx, "Get contacts trend successfully"))
	return
}
