package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

type AbnormalRecipient struct {
	Id          int    `json:"id"          dc:"Group ID"`
	Recipient   string `json:"recipient"   dc:"Recipient Email"`
	CreateTime  int    `json:"create_time" dc:"Create Time"`
	Description string `json:"description" dc:"Description"`
	Count       int    `json:"count"       dc:"Count"`
	AddType     int    `json:"add_type"    dc:"Add Type"`
	// AddType:Description     1: Manually added, 2: Automatically scanned, 3: Manually scanned
}

type ListAbnormalRecipientReq struct {
	g.Meta        `path:"/abnormal_recipient/list" method:"get" tags:"Abnormal Recipient" summary:"List abnormal recipients"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Page          int    `json:"page" v:"required|min:1" dc:"Page Number"`
	PageSize      int    `json:"page_size" v:"required|min:1" dc:"Page Size"`
	Keyword       string `json:"keyword" dc:"Search Keyword"`
	AddType       int    `json:"add_type" dc:"Add Type"`
}

type ListAbnormalRecipientRes struct {
	api_v1.StandardRes
	Data struct {
		Total int                  `json:"total" dc:"Total Count"`
		List  []*AbnormalRecipient `json:"list" dc:"Abnormal Recipient List"`
	} `json:"data"`
}

type AddAbnormalRecipientReq struct {
	g.Meta        `path:"/abnormal_recipient/add" method:"post" tags:"Abnormal Recipient" summary:"Add abnormal recipient"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Recipient     string `json:"recipient" v:"required|email" dc:"Recipient Email"`
}

type AddAbnormalRecipientRes struct {
	api_v1.StandardRes
}

type DeleteAbnormalRecipientReq struct {
	g.Meta        `path:"/abnormal_recipient/delete" method:"post" tags:"Abnormal Recipient" summary:"Delete abnormal recipient"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Id            int    `json:"id" v:"required|min:1" dc:"ID"`
}

type DeleteAbnormalRecipientRes struct {
	api_v1.StandardRes
}

type CheckGroupReq struct {
	g.Meta        `path:"/abnormal_recipient/check_group" method:"post" tags:"Abnormal Recipient" summary:"Check group emails and handle abnormal"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	GroupId       int    `json:"group_id" v:"required|min:1" dc:"Contact Group ID"`
	Oper          int    `json:"oper" v:"required|in:1,2,3" dc:"Operation type (1: only check, 2: add to exception table, 3: delete within group)"`
}

type CheckGroupRes struct {
	api_v1.StandardRes
}

type AbnormalSwitchReq struct {
	g.Meta        `path:"/abnormal_recipient/check_switch" method:"get" tags:"Abnormal Recipient" summary:"Abnormal Switch"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
}

type AbnormalSwitchRes struct {
	api_v1.StandardRes
}

type SetAbnormalSwitchReq struct {
	g.Meta        `path:"/abnormal_recipient/set_check_switch" method:"post" tags:"Abnormal Recipient" summary:"Abnormal Switch"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Oper          int    `json:"oper" v:"required|in:0,1" dc:"Operation type (1 for on, 0 for off)"`
}

type SetAbnormalSwitchRes struct {
	api_v1.StandardRes
}

type ClearabnormalRecipientReq struct {
	g.Meta        `path:"/abnormal_recipient/clear_abnormal" method:"post" tags:"Abnormal Recipient" summary:"Check group emails and handle abnormal"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
}

type ClearabnormalRecipientRes struct {
	api_v1.StandardRes
}

type GetScanLogReq struct {
	g.Meta        `path:"/abnormal_recipient/get_scan_log" method:"post" tags:"Abnormal Recipient" summary:"Get Scan Log"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
}

type GetScanLogRes struct {
	api_v1.StandardRes
}
