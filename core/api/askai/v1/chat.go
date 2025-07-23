package v1

import (
	"billionmail-core/utility/types/api_v1"

	"github.com/gogf/gf/v2/frame/g"
)

type CreateChatReq struct {
	g.Meta   `path:"/askai/chat/create_chat" method:"post" tags:"AskAi" summary:"create chat"`
	Domain   string `json:"domain" dc:"domain" v:"required#domain is required"`
	AddType  int    `json:"add_type" dc:"add type" v:"required#add type is required"`              // 1: add chat, 2: add knowledge base file
	TempName string `json:"temp_name" dc:"temporary name" v:"required#temporary name is required"` // Temporary name for the chat or knowledge base file
}

type CreateChatRes struct {
	api_v1.StandardRes
}

type GetChatListReq struct {
	g.Meta `path:"/askai/chat/get_chat_list" method:"post" tags:"AskAi" summary:"get chat list"`
}

type GetChatListRes struct {
	api_v1.StandardRes
}

// InfoReq is the request structure for retrieving chat information in AskAi.
type InfoReq struct {
	g.Meta `path:"/askai/chat/info" method:"post" tags:"AskAi" summary:"get chat info"`
	ChatId string `json:"chatId" dc:"chat id" v:"required#chat id is required"`
}

type InfoRes struct {
	api_v1.StandardRes
}

// ChatReq is the request structure for sending a chat message in AskAi.
type ChatReq struct {
	g.Meta       `path:"/askai/chat/chat" method:"post,get" tags:"AskAi" summary:"send chat message"`
	ChatId       string `json:"chatId" dc:"chat id" v:"required#chat id is required"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	ModelId      string `json:"model_id" dc:"model id" v:"required#model id is required"`
	Content      string `json:"content" dc:"content" v:"required#content is required"`
	IsText       bool   `json:"is_text" dc:"is text"` // true: text, false: json
}
type ChatRes struct {
	api_v1.StandardRes
}

type RemoveChatReq struct {
	g.Meta `path:"/askai/chat/remove_chat" method:"post" tags:"AskAi" summary:"remove chat"`
	ChatId string `json:"chatId" dc:"chat id" v:"required#chat id is required"`
}
type RemoveChatRes struct {
	api_v1.StandardRes
}

// StopReq is the request structure for stopping a chat in AskAi.
type StopReq struct {
	g.Meta `path:"/askai/chat/stop" method:"post" tags:"AskAi" summary:"stop chat"`
	ChatId string `json:"chatId" dc:"chat id" v:"required#chat id is required"`
}
type StopRes struct {
	api_v1.StandardRes
}

// GetHtmlReq is the request structure for retrieving HTML content in AskAi.
type GetHtmlReq struct {
	g.Meta `path:"/askai/chat/get_html" method:"post" tags:"AskAi" summary:"get html content"`
	ChatId string `json:"chatId" dc:"chat id" v:"required#chat id is required"`
}
type GetHtmlRes struct {
	api_v1.StandardRes
}

// ModifyHtmlReq is the request structure for modifying HTML content in AskAi.
type ModifyHtmlReq struct {
	g.Meta  `path:"/askai/chat/modify_html" method:"post" tags:"AskAi" summary:"modify html content"`
	ChatId  string `json:"chatId" dc:"chat id" v:"required#chat id is required"`
	Content string `json:"content" dc:"content" v:"required#content is required"`
}
type ModifyHtmlRes struct {
	api_v1.StandardRes
}

// CopyChatReq is the request structure for copying a chat in AskAi.
type CopyChatReq struct {
	g.Meta `path:"/askai/chat/copy_chat" method:"post" tags:"AskAi" summary:"copy chat"`
	ChatId string `json:"chatId" dc:"chat id" v:"required#chat id is required"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}

type CopyChatRes struct {
	api_v1.StandardRes
}
