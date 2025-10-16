package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

// UnsubscribeReq defines the unsubscribe request parameters
type UnsubscribeReq struct {
	g.Meta  `path:"/unsubscribe" method:"post" tags:"Unsubscribe" summary:"Unsubscribe from mailing lists"`
	Jwt     string `json:"jwt" v:"required" dc:"JWT token containing unsubscribe information"`
	GroupId []int  `json:"group_id" dc:"Group IDs to unsubscribe from (optional, if empty will unsubscribe from all groups)"`
}

// UnsubscribeRes defines the unsubscribe response
type UnsubscribeRes struct {
	api_v1.StandardRes
}

type GetUserGroupsReq struct {
	g.Meta `path:"/unsubscribe/user_group" method:"post" tags:"Unsubscribe" summary:"get user groups"`
	Email  string `json:"email" dc:"user email"`
}

type GetUserGroupsRes struct {
	api_v1.StandardRes
	Data []*GroupInfo `json:"data" dc:"user groups"`
}

type UnsubscribeNewReq struct {
	g.Meta `path:"/unsubscribe_new" method:"post" tags:"Unsubscribe" summary:"New unsubscribe API - direct unsubscribe"`
	Jwt    string `json:"jwt" v:"required" dc:"JWT token containing unsubscribe information"`
}

type UnsubscribeNewRes struct {
	api_v1.StandardRes
	Data UnsubscribeResult `json:"data" dc:"Unsubscribe result"`
}

type UnsubscribeResult struct {
	Email       string `json:"email" dc:"Email address"`
	GroupName   string `json:"group_name" dc:"Group name"`
	RedirectUrl string `json:"redirect_url" dc:"Redirect URL after unsubscribe"`
}
