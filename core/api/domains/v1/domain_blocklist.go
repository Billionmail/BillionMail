package v1

import (
	"billionmail-core/utility/types/api_v1"

	"github.com/gogf/gf/v2/frame/g"
)

// 手动调用黑名单检查
type CheckBlacklistReq struct {
	g.Meta        `path:"/domain_blocklist/check" tags:"Domain" method:"post" sm:"CheckBlacklist" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	ARecord       string `json:"a_record" v:"required|domain"`
}

type CheckBlacklistRes struct {
	api_v1.StandardRes
}

// 获取检查日志
type GetBlocklistCheckLogsReq struct {
	g.Meta        `path:"/domain_blocklist/logs" tags:"Domain" method:"get" sm:"GetBlocklistCheckLogs" in:"query"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Path          string `json:"path" v:"required"`
}

type GetBlocklistCheckLogsRes struct {
	api_v1.StandardRes
}
