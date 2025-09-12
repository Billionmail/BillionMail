package overview

import (
	"billionmail-core/internal/service/maillog_stat"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/util/gconv"
	"time"

	"billionmail-core/api/overview/v1"
)

func (c *ControllerV1) FailedList(ctx context.Context, req *v1.FailedListReq) (res *v1.FailedListRes, err error) {
	res = &v1.FailedListRes{}

	if req.EndTime == 0 {
		req.EndTime = time.Now().Unix()
	}

	if req.EndTime < req.StartTime {
		err = fmt.Errorf("start time must be greater or equal to end time")
		return
	}

	overview := maillog_stat.NewOverview()
	failedList := overview.FailedList(req.CampaignId, req.Domain, req.StartTime, req.EndTime)

	err = gconv.Struct(failedList, &res.Data)

	if err != nil {
		err = fmt.Errorf("failed to convert overview data: %v", err)
		return
	}

	res.SetSuccess(public.LangCtx(ctx, "Success"))

	return
}
