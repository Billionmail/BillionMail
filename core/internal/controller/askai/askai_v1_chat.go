package askai

import (
	v1 "billionmail-core/api/askai/v1"
	"billionmail-core/internal/service/askai"
	"context"
)

// Chat related methods
// Info(req *v1.InfoReq) (res *v1.InfoRes, err error)
// Chat(req *v1.ChatReq) (res *v1.ChatRes, err error)
// Stop(req *v1.StopReq) (res *v1.StopRes, err error)
// GetHtml(req *v1.GetHtmlReq) (res *v1.GetHtmlRes, err error)
// ModifyHtml(req *v1.ModifyHtmlReq) (res *v1.ModifyHtmlRes, err error)

func (c *ControllerV1) CreateChat(ctx context.Context, req *v1.CreateChatReq) (res *v1.CreateChatRes, err error) {
	res = &v1.CreateChatRes{}
	chatId, err := askai.CreateChat(req.Domain, req.AddType, req.TempName)
	if err != nil {
		res.SetError(err)
	} else {
		res.Data = map[string]string{"chatId": chatId}
		res.SetSuccess("Chat created successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetChatList(ctx context.Context, req *v1.GetChatListReq) (res *v1.GetChatListRes, err error) {
	res = &v1.GetChatListRes{}
	res.Data, err = askai.GetChatList()
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Chat list retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) Info(ctx context.Context, req *v1.InfoReq) (res *v1.InfoRes, err error) {
	res = &v1.InfoRes{}
	res.Data, err = askai.GetChatInfo(req.ChatId)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Chat info retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) Chat(ctx context.Context, req *v1.ChatReq) (res *v1.ChatRes, err error) {
	res = &v1.ChatRes{}
	err = askai.Chat(ctx, req.ChatId, req.SupplierName, req.ModelId, req.Content, req.IsText)
	if err != nil {
		res.SetError(err)
		return res, nil
	}
	return
}

func (c *ControllerV1) Stop(ctx context.Context, req *v1.StopReq) (res *v1.StopRes, err error) {
	res = &v1.StopRes{}
	err = askai.Stop(req.ChatId)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Chat stopped successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetHtml(ctx context.Context, req *v1.GetHtmlReq) (res *v1.GetHtmlRes, err error) {
	res = &v1.GetHtmlRes{}
	htmlContent, err := askai.GetHtml(req.ChatId)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("HTML content retrieved successfully")
		res.Data = map[string]interface{}{
			"html_content": htmlContent,
			"last_usage":   askai.GetLastUsage(req.ChatId),
		}
	}
	return res, nil
}

func (c *ControllerV1) ModifyHtml(ctx context.Context, req *v1.ModifyHtmlReq) (res *v1.ModifyHtmlRes, err error) {
	res = &v1.ModifyHtmlRes{}
	err = askai.ModifyHtml(req.ChatId, req.Content)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("HTML content modified successfully")
	}

	return res, nil
}

func (c *ControllerV1) RemoveChat(ctx context.Context, req *v1.RemoveChatReq) (res *v1.RemoveChatRes, err error) {
	res = &v1.RemoveChatRes{}
	// Logic to remove the chat based on req.ChatId
	// This is a placeholder implementation
	err = askai.RemoveChat(req.ChatId)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Chat removed successfully")
	}
	return res, nil
}

func (c *ControllerV1) CopyChat(ctx context.Context, req *v1.CopyChatReq) (res *v1.CopyChatRes, err error) {
	res = &v1.CopyChatRes{}
	chatId, content, err := askai.CopyChat(req.ChatId, req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.Data = map[string]string{"chatId": chatId, "content": content}
		res.SetSuccess("Chat copied successfully")
	}
	return res, nil
}
