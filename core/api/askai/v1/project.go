package v1

import (
	"billionmail-core/utility/types/api_v1"

	"github.com/gogf/gf/v2/frame/g"
)

// CreateReq is the request structure for creating a new project configuration in AskAi.
type CreateReq struct {
	g.Meta `path:"/askai/project/create" method:"post" tags:"AskAi" summary:"create project config"`
	Domain string   `json:"domain" dc:"domain" v:"required#domain is required"`
	Urls   []string `json:"urls" dc:"urls"`
}
type CreateRes struct {
	api_v1.StandardRes
}

// GetBaseInfoReq is the request structure for retrieving the base information of a project in AskAi.
type GetBaseInfoReq struct {
	g.Meta `path:"/askai/project/get_base_info" method:"post" tags:"AskAi" summary:"get project base info"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}
type GetBaseInfoRes struct {
	api_v1.StandardRes
}

// ModifyBaseInfoReq is the request structure for modifying the base information of a project in AskAi.
type ModifyBaseInfoReq struct {
	g.Meta        `path:"/askai/project/modify_base_info" method:"post" tags:"AskAi" summary:"modify project base info"`
	Domain        string   `json:"domain" dc:"domain" v:"required#domain is required"`
	ProjectName   string   `json:"project_name" dc:"project name" v:"required#project name is required"`
	Description   string   `json:"description" dc:"project description"`
	Industry      string   `json:"industry" dc:"project industry"`
	PrimaryLogo   string   `json:"primary_logo" dc:"primary logo"`
	SecondaryLogo string   `json:"secondary_logo" dc:"secondary logo"`
	Favicon       string   `json:"favicon" dc:"favicon"`
	Urls          []string `json:"urls" dc:"urls"`
}
type ModifyBaseInfoRes struct {
	api_v1.StandardRes
}

// ModifyKnowledgeBaseFileReq is the request structure for modifying a knowledge base file in AskAi.
type ModifyKnowledgeBaseFileReq struct {
	g.Meta  `path:"/askai/project/modify_knowledge_base_file" method:"post" tags:"AskAi" summary:"modify knowledge base file"`
	Domain  string `json:"domain" dc:"domain" v:"required#domain is required"`
	Kid     string `json:"kid" dc:"knowledge base file id" v:"required#knowledge base file id is required"`
	Title   string `json:"title" dc:"title" v:"required#title is required"`
	Content string `json:"content" dc:"content" v:"required#content is required"`
}
type ModifyKnowledgeBaseFileRes struct {
	api_v1.StandardRes
}

// CreateKnowledgeBaseFileReq is the request structure for creating a new knowledge base file in AskAi.
type CreateKnowledgeBaseFileReq struct {
	g.Meta  `path:"/askai/project/create_knowledge_base_file" method:"post" tags:"AskAi" summary:"create knowledge base file"`
	Domain  string `json:"domain" dc:"domain" v:"required#domain is required"`
	Title   string `json:"title" dc:"title" v:"required#title is required"`
	Content string `json:"content" dc:"content" v:"required#content is required"`
}
type CreateKnowledgeBaseFileRes struct {
	api_v1.StandardRes
}

// RemoveKnowledgeBaseFileReq is the request structure for removing a knowledge base file in AskAi.
type RemoveKnowledgeBaseFileReq struct {
	g.Meta `path:"/askai/project/remove_knowledge_base_file" method:"post" tags:"AskAi" summary:"remove knowledge base file"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
	Kid    string `json:"kid" dc:"knowledge base file id" v:"required#knowledge base file id is required"`
}
type RemoveKnowledgeBaseFileRes struct {
	api_v1.StandardRes
}

// GetCompanyProfileReq is the request structure for retrieving the company profile in AskAi.
type GetCompanyProfileReq struct {
	g.Meta `path:"/askai/project/get_company_profile" method:"post" tags:"AskAi" summary:"get company profile"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}
type GetCompanyProfileRes struct {
	api_v1.StandardRes
}

// ModifyCompanyProfileReq is the request structure for modifying the company profile in AskAi.
type ModifyCompanyProfileReq struct {
	g.Meta           `path:"/askai/project/modify_company_profile" method:"post" tags:"AskAi" summary:"modify company profile"`
	Domain           string `json:"domain" dc:"domain" v:"required#domain is required"`
	LegalCompanyName string `json:"legal_company_name" dc:"legal company name"`
	Website          string `json:"website" dc:"website"`
	CompanyProfile   string `json:"company_profile" dc:"company profile"`
	Email            string `json:"email" dc:"email"`
	Phone            string `json:"phone" dc:"phone"`
	SupportUrl       string `json:"support_url" dc:"support url"`
}

type ModifyCompanyProfileRes struct {
	api_v1.StandardRes
}

// GetStyleConfigReq is the request structure for retrieving the style configuration of a project in AskAi.
type GetStyleConfigReq struct {
	g.Meta `path:"/askai/project/get_style_config" method:"post" tags:"AskAi" summary:"get style config"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}

type GetStyleConfigRes struct {
	api_v1.StandardRes
}

// ModifyStyleConfigReq is the request structure for modifying the style configuration of a project in AskAi.
type ModifyStyleConfigReq struct {
	g.Meta              `path:"/askai/project/modify_style_config" method:"post" tags:"AskAi" summary:"modify style config"`
	Domain              string `json:"domain" dc:"domain" v:"required#domain is required"`
	AccentColor         string `json:"accent_color" dc:"accent color"`
	TextColor           string `json:"text_color" dc:"text color"`
	PageBackground      string `json:"page_background" dc:"page background"`
	ContainerBackground string `json:"container_background" dc:"container background"`
	LinkSocialColor     string `json:"link_social_color" dc:"link social color"`
	LinkFooterColor     string `json:"link_footer_color" dc:"link footer color"`
	HeadingFont         string `json:"heading_font" dc:"heading font"`
	BodyFont            string `json:"body_font" dc:"body font"`
}
type ModifyStyleConfigRes struct {
	api_v1.StandardRes
}

// GetSitemapReq is the request structure for retrieving the sitemap of a project in AskAi.
type GetSitemapReq struct {
	g.Meta `path:"/askai/project/get_sitemap" method:"post" tags:"AskAi" summary:"get sitemap"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}
type GetSitemapRes struct {
	api_v1.StandardRes
}

// RemoveSitemapNodeReq is the request structure for removing a node from the sitemap of a project in AskAi.
type RemoveSitemapNodeReq struct {
	g.Meta  `path:"/askai/project/remove_sitemap_node" method:"post" tags:"AskAi" summary:"remove sitemap node"`
	Domain  string `json:"domain" dc:"domain" v:"required#domain is required"`
	UriPath string `json:"uri_path" dc:"uri path" v:"required#uri path is required"`
}

type RemoveSitemapNodeRes struct {
	api_v1.StandardRes
}

// AddSitemapNodeReq is the request structure for adding a node to the sitemap of a project in AskAi.
type AddSitemapNodeReq struct {
	g.Meta  `path:"/askai/project/add_sitemap_node" method:"post" tags:"AskAi" summary:"add sitemap node"`
	Domain  string `json:"domain" dc:"domain" v:"required#domain is required"`
	Title   string `json:"title" dc:"title" v:"required#title is required"`
	UriPath string `json:"uri_path" dc:"uri path" v:"required#uri path is required"`
}
type AddSitemapNodeRes struct {
	api_v1.StandardRes
}

// GetFooterReq is the request structure for retrieving the footer configuration of a project in AskAi.
type GetFooterReq struct {
	g.Meta `path:"/askai/project/get_footer" method:"post" tags:"AskAi" summary:"get footer config"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}
type GetFooterRes struct {
	api_v1.StandardRes
}

// ModifyFooterReq is the request structure for modifying the footer configuration of a project in AskAi.
type ModifyFooterReq struct {
	g.Meta        `path:"/askai/project/modify_footer" method:"post" tags:"AskAi" summary:"modify footer config"`
	Domain        string `json:"domain" dc:"domain" v:"required#domain is required"`
	CopyrightText string `json:"copyright_text" dc:"copyright text" v:"required#copyright text is required"`
	Disclaimer    string `json:"disclaimer" dc:"disclaimer" v:"required#disclaimer is required"`
}
type ModifyFooterRes struct {
	api_v1.StandardRes
}

// GetPromptReq is the request structure for retrieving the prompt configuration of a project in AskAi.
type GetPromptReq struct {
	g.Meta `path:"/askai/project/get_prompt" method:"post" tags:"AskAi" summary:"get prompt config"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}
type GetPromptRes struct {
	api_v1.StandardRes
}

// ModifyPromptReq is the request structure for modifying the prompt configuration of a project in AskAi.
type ModifyPromptReq struct {
	g.Meta `path:"/askai/project/modify_prompt" method:"post" tags:"AskAi" summary:"modify prompt config"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
	Prompt string `json:"prompt" dc:"prompt" v:"required#prompt is required"`
}
type ModifyPromptRes struct {
	api_v1.StandardRes
}

// UploadImageReq is the request structure for uploading an image to a project in AskAi.
type UploadImageReq struct {
	g.Meta   `path:"/askai/project/upload_image" method:"post" tags:"AskAi" summary:"upload image"`
	Domain   string `json:"domain" dc:"domain" v:"required#domain is required"`
	Image    string `json:"image" dc:"image" v:"required#image is required"`
	Filename string `json:"filename" dc:"filename" v:"required#filename is required"`
	AltText  string `json:"alt_text" dc:"alt text" v:"required#alt text is required"`
	ImageTag string `json:"image_tag" dc:"image tag" v:"required#image tag is required" d:"Image tag is used to identify the image in the project, e.g., 'logo', 'banner', etc."`
}

type UploadImageRes struct {
	api_v1.StandardRes
}

// ModifyImageReq is the request structure for modifying an existing image in a project in AskAi.
type ModifyImageReq struct {
	g.Meta   `path:"/askai/project/modify_image" method:"post" tags:"AskAi" summary:"modify image"`
	Domain   string `json:"domain" dc:"domain" v:"required#domain is required"`
	ImageId  string `json:"image_id" dc:"image id" v:"required#image id is required"`
	AltText  string `json:"alt_text" dc:"alt text" v:"required#alt text is required"`
	ImageTag string `json:"image_tag" dc:"image tag" v:"required#image tag is required" d:"Image tag is used to identify the image in the project, e.g., 'logo', 'banner', etc."`
}
type ModifyImageRes struct {
	api_v1.StandardRes
}

// RemoveImageReq is the request structure for removing an image from a project in AskAi.
type RemoveImageReq struct {
	g.Meta  `path:"/askai/project/remove_image" method:"post" tags:"AskAi" summary:"remove image"`
	Domain  string `json:"domain" dc:"domain" v:"required#domain is required"`
	ImageId string `json:"image_id" dc:"image id" v:"required#image id is required"`
}

type RemoveImageRes struct {
	api_v1.StandardRes
}

// GetImagesReq is the request structure for retrieving images associated with a project in AskAi.
type GetImagesReq struct {
	g.Meta `path:"/askai/project/get_images" method:"post" tags:"AskAi" summary:"get images"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}

type GetImagesRes struct {
	api_v1.StandardRes
}

// GetProjectStatusReq is the request structure for retrieving the status of a project in AskAi.
type GetProjectStatusReq struct {
	g.Meta `path:"/askai/project/get_project_status" method:"post" tags:"AskAi" summary:"get project status"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
}
type GetProjectStatusRes struct {
	api_v1.StandardRes
}

// SetProjectStatusReq is the request structure for setting the status of a project in AskAi.
type SetProjectStatusReq struct {
	g.Meta `path:"/askai/project/set_project_status" method:"post" tags:"AskAi" summary:"set project status"`
	Domain string `json:"domain" dc:"domain" v:"required#domain is required"`
	Status bool   `json:"status" dc:"status" v:"required#status is required"`
}

type SetProjectStatusRes struct {
	api_v1.StandardRes
}
