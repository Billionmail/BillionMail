package v1

import (
	"billionmail-core/internal/model/entity"
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

type GetOperationLogReq struct {
	g.Meta        `path:"/operation_log/list" method:"get" tags:"Operation Log" summary:"List operation logs"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Page          int    `json:"page" v:"required|min:1" dc:"Page Number"`
	PageSize      int    `json:"page_size" v:"required|min:1" dc:"Page Size"`
	Keyword       string `json:"keyword" dc:"Search Keyword"`
	Type          string `json:"type"`
	StartTime     int    `json:"start_time" dc:"start time"`
	EndTime       int    `json:"end_time" dc:"end time"`
}

type GetOperationLogRes struct {
	api_v1.StandardRes
	Data struct {
		Total int                   `json:"total" dc:"Total Count"`
		List  []entity.OperationLog `json:"list" dc:"Operation Log List"`
		Type  map[string]string     `json:"type"`
	} `json:"data"`
}
