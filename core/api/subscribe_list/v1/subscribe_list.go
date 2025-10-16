package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

type ContactGroup struct {
	Id          int    `json:"id"          dc:"Group ID"`
	Name        string `json:"name"        dc:"Group Name"`
	Description string `json:"description" dc:"Description"`
	CreateTime  int    `json:"create_time" dc:"Create Time"`
	UpdateTime  int    `json:"update_time" dc:"Update Time"`
	Token       string `json:"token"      dc:"Subscription Token"`
	DoubleOptin int    `json:"double_optin" dc:"Double Opt-in Status(0: Single Opt-in 1: Double Opt-in)"`

	WelcomeHtml string `json:"welcome_mail_html" dc:"Welcome Email Html"`
	WelcomeDrag string `json:"welcome_mail_drag" dc:"Welcome Email Drag"`

	WelcomeSubject   string `json:"welcome_subject" dc:"Welcome Email Subject"`
	SendWelcomeEmail int    `json:"send_welcome_email" dc:"Whether to send a welcome email"`
	ConfirmSubject   string `json:"confirm_subject" dc:"Confirmation Email Subject"`

	ConfirmHtml   string `json:"confirm_mail_html" dc:"Confirmation Email Html"`
	ConfirmDrag   string `json:"confirm_mail_drag" dc:"Confirmation Email Drag"`
	SuccessUrl    string `json:"success_url" dc:"Success URL"`
	ConfirmUrl    string `json:"confirm_url" dc:"Confirmation URL"`
	AlreadyUrl    string `json:"already_url" dc:"Already Subscribed URL"`
	SubscribeForm string `json:"subscribe_form" dc:"Subscription Form HTML"`
}
type Contact struct {
	Id           int               `json:"id"          dc:"Contact ID"`
	Email        string            `json:"email"       dc:"Email Address"`
	GroupId      int               `json:"group_id"    dc:"Group ID"`
	Active       int               `json:"active"      dc:"Status(1:Subscribed 0:Unsubscribed)"`
	TaskId       int               `json:"task_id"     dc:"Bulk Mail Task ID"`
	CreateTime   int               `json:"create_time" dc:"Create Time"`
	Status       int               `json:"status"      dc:"Status( 1:Confirmed   0:Unconfirmed)"`
	Attribs      map[string]string `json:"attribs"`
	LastActiveAt int               `json:"last_active_at" dc:"Last Active At"`
}

type SubscribeSubmitReq struct {
	g.Meta  `path:"/subscribe/submit" tags:"Subscribe" method:"post" summary:"Subscribe to the service"`
	Email   string            `json:"email" dc:"Email address for subscription"`
	Token   string            `json:"token" dc:"Subscription token"`
	Attribs map[string]string `json:"attribs" dc:"Additional attributes for subscription, e.g., {'name': 'John Doe', 'phone': '1234567890'}"`
}

type SubscribeSubmitRes struct {
	api_v1.StandardRes
}

type SubscribeConfirmReq struct {
	g.Meta `path:"/subscribe/confirm" tags:"Subscribe" method:"get" summary:"Confirm subscription"`
	Token  string `json:"token" dc:"Subscription token"`
	Email  string `json:"email" dc:"Email address for subscription"`
}

type SubscribeConfirmRes struct {
	api_v1.StandardRes
}
