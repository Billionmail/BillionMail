package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

type QueueMailItem struct {
	QueueID      string      `json:"queue_id" dc:"Queue ID"`
	Sender       string      `json:"sender" dc:"Sender"`
	Recipients   []Recipient `json:"recipients" dc:"Recipient list"`
	ArrivalTime  int64       `json:"arrival_time" dc:"Arrival timestamp"`
	DelayReason  string      `json:"delay_reason,omitempty" dc:"Delay reason"`
	MessageSize  int         `json:"message_size,omitempty" dc:"Message size in bytes"`
	QueueName    string      `json:"queue_name" dc:"Queue name"`
	ForcedExpire bool        `json:"forced_expire" dc:"Forced expire flag"`
	Recipient    string      `json:"recipient" dc:"Recipient"`
}

type Recipient struct {
	Address     string `json:"address" dc:"Recipient address"`
	DelayReason string `json:"delay_reason,omitempty" dc:"Delay reason"`
}

type GetPostfixQueueListReq struct {
	g.Meta        `path:"/postfix_queue/list" method:"get" summary:"Get postfix queue list"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" desc:"Domain filter"`
}

type GetPostfixQueueListRes struct {
	api_v1.StandardRes
	Data struct {
		List  []QueueMailItem `json:"list" dc:"Postfix queue list"`
		Total int             `json:"total" dc:"Total count"`
	} `json:"data"`
}

type GetPostfixQueueInfoReq struct {
	g.Meta        `path:"/postfix_queue/queue_info" method:"get" summary:"View mail content of specified queue"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	QueueID       string `json:"queue_id" v:"required" dc:"Queue ID"`
}

type GetPostfixQueueInfoRes struct {
	api_v1.StandardRes
}

type DeletePostfixQueueByIdReq struct {
	g.Meta        `path:"/postfix_queue/delete_by_id" method:"post" summary:"Delete specified queue mails (batch supported)"`
	Authorization string   `json:"authorization" dc:"Authorization" in:"header"`
	QueueIDs      []string `json:"queue_ids" v:"required" dc:"Queue ID list"`
}

type DeletePostfixQueueByIdRes struct {
	api_v1.StandardRes
}

type DeleteAllDeferredQueueReq struct {
	g.Meta        `path:"/postfix_queue/delete" method:"post" summary:"Clear all deferred queue"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
}

type DeleteAllDeferredQueueRes struct {
	api_v1.StandardRes
}

type FlushPostfixQueueReq struct {
	g.Meta        `path:"/postfix_queue/flush" method:"post" summary:"Force send all mail queue"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" dc:"Optional, specify domain to force send"`
}

type FlushPostfixQueueRes struct {
	api_v1.StandardRes
}

type FlushPostfixQueueByIdReq struct {
	g.Meta        `path:"/postfix_queue/flush_by_id" method:"post" summary:"Flush specified queue mails (batch supported)"`
	Authorization string   `json:"authorization" dc:"Authorization" in:"header"`
	QueueIDs      []string `json:"queue_ids" v:"required" dc:"Queue ID list"`
}

type FlushPostfixQueueByIdRes struct {
	api_v1.StandardRes
}

type SetPostfixConfigReq struct {
	g.Meta        `path:"/postfix_queue/set_config" method:"post" summary:"Set Postfix queue-related configuration items"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Key           string `json:"key" dc:"Configuration key"`
	Value         string `json:"value" dc:"Configuration value"`
}

type SetPostfixConfigRes struct {
	api_v1.StandardRes
}

type SetAllPostfixConfigReq struct {
	g.Meta               `path:"/postfix_queue/set_all_config" method:"post" summary:"批量设置Postfix队列相关配置项"`
	Authorization        string `json:"authorization" dc:"Authorization" in:"header"`
	BounceQueueLifetime  string `json:"bounce_queue_lifetime" dc:"Bounce queue lifetime"`
	MaximalBackoffTime   string `json:"maximal_backoff_time" dc:"Maximal backoff time"`
	MaximalQueueLifetime string `json:"maximal_queue_lifetime" dc:"Maximal queue lifetime"`
	MinimalBackoffTime   string `json:"minimal_backoff_time" dc:"Minimal backoff time"`
	QueueRunDelay        string `json:"queue_run_delay" dc:"Queue run delay"`
	TriggerTimeout       string `json:"trigger_timeout" dc:"Trigger timeout"`
}

type SetAllPostfixConfigRes struct {
	api_v1.StandardRes
}

type GetPostfixConfigReq struct {
	g.Meta        `path:"/postfix_queue/get_config" method:"get" summary:"Get Postfix queue-related configuration items"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
}

type GetPostfixConfigRes struct {
	api_v1.StandardRes
}
