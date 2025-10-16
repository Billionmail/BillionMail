package askai

import (
	v1 "billionmail-core/api/askai/v1"
	"billionmail-core/utility/types/api_v1"
)

type IAskAiV1 interface {
	// Supplier related methods
	List(req *v1.ListReq) (res *v1.ListRes, err error)
	Models(req *v1.ModelsReq) (res *v1.ModelsRes, err error)
	AddModel(req *v1.AddModelReq) (res *v1.AddModelRes, err error)
	RemoveModel(req *v1.RemoveModelReq) (res *v1.RemoveModelRes, err error)
	SetSupplierConfig(req *v1.SetSupplierConfigReq) (res *api_v1.StandardRes, err error)
	Testing(req *v1.TestingReq) (res *v1.TestingRes, err error)
	GetSupplierConfig(req *v1.GetSupplierConfigReq) (res *v1.GetSupplierConfigRes, err error)
	SetSupplierStatus(req *v1.SetSupplierStatusReq) (res *api_v1.StandardRes, err error)
	SetModelStatus(req *v1.SetModelStatusReq) (res *api_v1.StandardRes, err error)
	AddSupplier(req *v1.AddSupplierReq) (res *v1.AddSupplierRes, err error)
	RemoveSupplier(req *v1.RemoveSupplierReq) (res *v1.RemoveSupplierRes, err error)
	SetModelTitle(req *v1.SetModelTitleReq) (res *v1.SetModelTitleRes, err error)
	SetModelCapability(req *v1.SetModelCapabilityReq) (res *v1.SetModelCapabilityRes, err error)
	ModifyModel(req *v1.ModifyModelReq) (res *v1.ModifyModelRes, err error)
	Status(req *v1.StatusReq) (res *v1.StatusRes, err error)

	// Project related methods
	Create(req *v1.CreateReq) (res *v1.CreateRes, err error)
	GetBaseInfo(req *v1.GetBaseInfoReq) (res *v1.GetBaseInfoRes, err error)
	ModifyBaseInfo(req *v1.ModifyBaseInfoReq) (res *v1.ModifyBaseInfoRes, err error)
	ModifyKnowledgeBaseFile(req *v1.ModifyKnowledgeBaseFileReq) (res *v1.ModifyKnowledgeBaseFileRes, err error)
	CreateKnowledgeBaseFile(req *v1.CreateKnowledgeBaseFileReq) (res *v1.CreateKnowledgeBaseFileRes, err error)
	RemoveKnowledgeBaseFile(req *v1.RemoveKnowledgeBaseFileReq) (res *v1.RemoveKnowledgeBaseFileRes, err error)
	GetCompanyProfile(req *v1.GetCompanyProfileReq) (res *v1.GetCompanyProfileRes, err error)
	ModifyCompanyProfile(req *v1.ModifyCompanyProfileReq) (res *v1.ModifyCompanyProfileRes, err error)
	GetStyleConfig(req *v1.GetStyleConfigReq) (res *v1.GetStyleConfigRes, err error)
	ModifyStyleConfig(req *v1.ModifyStyleConfigReq) (res *v1.ModifyStyleConfigRes, err error)
	GetSitemap(req *v1.GetSitemapReq) (res *v1.GetSitemapRes, err error)
	RemoveSitemapNode(req *v1.RemoveSitemapNodeReq) (res *v1.RemoveSitemapNodeRes, err error)
	AddSitemapNode(req *v1.AddSitemapNodeReq) (res *v1.AddSitemapNodeRes, err error)
	GetFooter(req *v1.GetFooterReq) (res *v1.GetFooterRes, err error)
	ModifyFooter(req *v1.ModifyFooterReq) (res *v1.ModifyFooterRes, err error)
	GetPrompt(req *v1.GetPromptReq) (res *v1.GetPromptRes, err error)
	ModifyPrompt(req *v1.ModifyPromptReq) (res *v1.ModifyPromptRes, err error)
	UploadImage(req *v1.UploadImageReq) (res *v1.UploadImageRes, err error)
	RemoveImage(req *v1.RemoveImageReq) (res *v1.RemoveImageRes, err error)
	ModifyImage(req *v1.ModifyImageReq) (res *v1.ModifyImageRes, err error)
	GetImages(req *v1.GetImagesReq) (res *v1.GetImagesRes, err error)
	GetProjectStatus(req *v1.GetProjectStatusReq) (res *v1.GetProjectStatusRes, err error)
	SetProjectStatus(req *v1.SetProjectStatusReq) (res *v1.SetProjectStatusRes, err error)

	// Chat related methods
	CreateChat(req *v1.CreateChatReq) (res *v1.CreateChatRes, err error)
	GetChatList(req *v1.GetChatListReq) (res *v1.GetChatListRes, err error)
	Info(req *v1.InfoReq) (res *v1.InfoRes, err error)
	Chat(req *v1.ChatReq) (res *v1.ChatRes, err error)
	Stop(req *v1.StopReq) (res *v1.StopRes, err error)
	GetHtml(req *v1.GetHtmlReq) (res *v1.GetHtmlRes, err error)
	ModifyHtml(req *v1.ModifyHtmlReq) (res *v1.ModifyHtmlRes, err error)
	RemoveChat(req *v1.RemoveChatReq) (res *v1.RemoveChatRes, err error)
	CopyChat(req *v1.CopyChatReq) (res *v1.CopyChatRes, err error)
}
