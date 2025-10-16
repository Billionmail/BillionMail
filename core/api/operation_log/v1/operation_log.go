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
	} `json:"data"`
}

type GetOperationTypeReq struct {
	g.Meta        `path:"/operation_log/type_list" method:"get" tags:"Operation Type" summary:"Operation Type"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
}

type GetOperationTypeRes struct {
	api_v1.StandardRes
}
type GetOutputLogReq struct {
	g.Meta    `path:"/operation_log/output/list" method:"get" tags:"Output Log" summary:"List output logs"`
	StartDate string `json:"start_date" v:"required" dc:"Start date(YYYY-MM-DD)"`
	EndDate   string `json:"end_date" v:"required" dc:"End date(YYYY-MM-DD)"`
	Keyword   string `json:"keyword" dc:"keyword"`
	Page      int    `json:"page" v:"min:1" dc:"Page Number" d:"1"`
	PageSize  int    `json:"page_size" dc:"page size"`
}

type GetOutputLogRes struct {
	api_v1.StandardRes
}

type GetLatestOutputLogReq struct {
	g.Meta `path:"/operation_log/output/latest" method:"get" tags:"Output Log" summary:"Get latest output log"`
}
type GetLatestOutputLogRes struct {
	api_v1.StandardRes
}
