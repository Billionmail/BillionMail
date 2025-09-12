package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

// Mailbox defines the mailbox entity
type Mailbox struct {
	Username       string `json:"username"        dc:"Email address"`
	Password       string `json:"password"        dc:"Password"`
	PasswordEncode string `json:"password_encode" dc:"Encoded password"`
	FullName       string `json:"full_name"       dc:"Full name"`
	IsAdmin        int    `json:"is_admin"        dc:"Is administrator: 1-yes, 0-no"`
	Maildir        string `json:"maildir"         dc:"Mailbox directory"`
	Quota          int64  `json:"quota"           dc:"Mailbox quota"`
	LocalPart      string `json:"local_part"      dc:"Local part (username)"`
	Domain         string `json:"domain"          dc:"Domain name"`
	CreateTime     int64  `json:"create_time"     dc:"Creation time"`
	UpdateTime     int64  `json:"update_time"     dc:"Update time"`
	Active         int    `json:"active"          dc:"Status: 1-enabled, 0-disabled"`
}

type AddMailboxReq struct {
	g.Meta        `path:"/mailbox/create" tags:"MailBox" method:"post" summary:"Create mailbox" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`
	FullName      string `json:"full_name" v:"min-length:1" dc:"username"`
	LocalPart     string `json:"local_part" v:"required|min-length:1|regex:[\\w-]{1,}" dc:"local_part"`
	Password      string `json:"password" v:"required|min-length:8" dc:"Password"`
	Active        int    `json:"active" v:"required" dc:"Status" d:"1"`
	IsAdmin       int    `json:"isAdmin" v:"required" dc:"IsAdmin" d:"0"`
	Quota         int    `json:"quota" v:"required|min:1" dc:"Quota" d:"5242880"`
}

type AddMailboxRes struct {
	api_v1.StandardRes
}

type BatchAddMailboxReq struct {
	g.Meta        `path:"/mailbox/batch_create" tags:"MailBox" method:"post" summary:"Batch create mailbox" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`

	Quota  int    `json:"quota" v:"required|min:1" dc:"Quota" d:"5242880"`
	Count  int    `json:"count" v:"required|min:2" dc:"Count" d:"10"`
	Prefix string `json:"prefix" v:"regex:[\\w-]{0,}" dc:"Email name prefix, optional" d:"user"`
}

type BatchAddMailboxRes struct {
	api_v1.StandardRes
}

type UpdateMailboxReq struct {
	g.Meta        `path:"/mailbox/update" tags:"MailBox" method:"post" summary:"Update mailbox" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`
	FullName      string `json:"full_name" v:"min-length:1" dc:"username"`
	LocalPart     string `json:"local_part" v:"required|min-length:1|regex:[\\w-]{1,}" dc:"local_part"`
	Password      string `json:"password" v:"required|min-length:8" dc:"Password"`
	Active        int    `json:"active" v:"required" dc:"Status" d:"1"`
	IsAdmin       int    `json:"isAdmin" v:"required" dc:"IsAdmin" d:"0"`
	Quota         int    `json:"quota" v:"required|min:1" dc:"Quota" d:"5242880"`
}

type UpdateMailboxRes struct {
	api_v1.StandardRes
}

type DeleteMailboxReq struct {
	g.Meta        `path:"/mailbox/delete" tags:"MailBox" method:"post" summary:"Delete mailbox (batch supported)" in:"body"`
	Authorization string   `json:"authorization" dc:"Authorization" in:"header"`
	Emails        []string `json:"emails" v:"required" dc:"Email address list for delete"`
}

type DeleteMailboxRes struct {
	api_v1.StandardRes
}
type MailboxWithMxRecord struct {
	Mailbox
	MxRecord string `json:"mx" dc:"MX record for the domain"`
}
type GetMailboxReq struct {
	g.Meta        `path:"/mailbox/list" tags:"MailBox" method:"get" summary:"Get mailbox" in:"query"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Keyword       string `json:"keyword" dc:"Keyword"`
	Domain        string `json:"domain" v:"domain" dc:"Domain"`
	Page          int    `json:"page" v:"min:1" dc:"Page" d:"1"`
	PageSize      int    `json:"page_size" v:"min:1" dc:"Page size" d:"20"`
}

type GetMailboxRes struct {
	api_v1.StandardRes
	Data struct {
		Total int                   `json:"total"`
		List  []MailboxWithMxRecord `json:"list"`
	} `json:"data"`
}

type GetAllMailboxReq struct {
	g.Meta        `path:"/mailbox/all" tags:"MailBox" method:"get" summary:"Get all mailbox" in:"query"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"domain" dc:"Domain"`
}

type GetAllMailboxRes struct {
	api_v1.StandardRes
	Data []Mailbox `json:"data"`
}

type GetAllEmailReq struct {
	g.Meta        `path:"/mailbox/all_email" tags:"MailBox" method:"get" summary:"Get all email" in:"query"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"domain" dc:"Domain"`
}

type GetAllEmailRes struct {
	api_v1.StandardRes
	Data []string `json:"data"` // List of email addresses
}

// 导出邮箱
type ExportMailboxReq struct {
	g.Meta        `path:"/mailbox/export" tags:"MailBox" method:"post" summary:"Export mailbox" in:"query"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"domain" dc:"Domain"`
	FileType      string `json:"file_type" v:"in:csv,txt,json" dc:"File type to export, csv or txt or json (default: csv)"`
}

type ExportMailboxRes struct {
	api_v1.StandardRes
}

// 导入邮箱
type ImportMailboxReq struct {
	g.Meta        `path:"/mailbox/import" tags:"MailBox" method:"post" summary:"Import mailbox" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	FileData      string `json:"file_data" v:"required" dc:"File data in base64 format"`
	FileType      string `json:"file_type" v:"in:csv,txt,json" dc:"File type to import, csv or txt or json (default: csv)"`
}

type ImportMailboxRes struct {
	api_v1.StandardRes
}
