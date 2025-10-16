package askai

import (
	v1 "billionmail-core/api/askai/v1"
	"billionmail-core/internal/service/askai"
	"context"
)

func (c *ControllerV1) Create(ctx context.Context, req *v1.CreateReq) (res *v1.CreateRes, err error) {
	res = &v1.CreateRes{}
	err = askai.Create(req.Domain, req.Urls)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Project created successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetProjectStatus(ctx context.Context, req *v1.GetProjectStatusReq) (res *v1.GetProjectStatusRes, err error) {
	res = &v1.GetProjectStatusRes{}
	projectStatus, createStatus, err := askai.GetProjectStatus(req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.Data = map[string]interface{}{
			"status":        projectStatus,
			"create_status": createStatus,
		}
		res.SetSuccess("Project status retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) SetProjectStatus(ctx context.Context, req *v1.SetProjectStatusReq) (res *v1.SetProjectStatusRes, err error) {
	res = &v1.SetProjectStatusRes{}
	err = askai.SetProjectStatus(req.Domain, req.Status)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Project status set successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetBaseInfo(ctx context.Context, req *v1.GetBaseInfoReq) (res *v1.GetBaseInfoRes, err error) {
	res = &v1.GetBaseInfoRes{}
	res.Data, err = askai.GetBaseInfo(req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Base information retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) ModifyBaseInfo(ctx context.Context, req *v1.ModifyBaseInfoReq) (res *v1.ModifyBaseInfoRes, err error) {
	res = &v1.ModifyBaseInfoRes{}
	err = askai.ModifyBaseInfo(req.Domain, req.ProjectName, req.Description, req.Industry, req.PrimaryLogo, req.SecondaryLogo, req.Favicon, req.Urls)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Base information modified successfully")
	}
	return res, nil
}

func (c *ControllerV1) ModifyKnowledgeBaseFile(ctx context.Context, req *v1.ModifyKnowledgeBaseFileReq) (res *v1.ModifyKnowledgeBaseFileRes, err error) {
	res = &v1.ModifyKnowledgeBaseFileRes{}
	err = askai.ModifyKnowledgeBaseFile(req.Domain, req.Kid, req.Title, req.Content)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Knowledge base file modified successfully")
	}
	return res, nil
}

func (c *ControllerV1) CreateKnowledgeBaseFile(ctx context.Context, req *v1.CreateKnowledgeBaseFileReq) (res *v1.CreateKnowledgeBaseFileRes, err error) {
	res = &v1.CreateKnowledgeBaseFileRes{}
	err = askai.CreateKnowledgeBaseFile(req.Domain, req.Title, req.Content, "")
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Knowledge base file created successfully")
	}
	return res, nil
}

func (c *ControllerV1) RemoveKnowledgeBaseFile(ctx context.Context, req *v1.RemoveKnowledgeBaseFileReq) (res *v1.RemoveKnowledgeBaseFileRes, err error) {
	res = &v1.RemoveKnowledgeBaseFileRes{}
	err = askai.RemoveKnowledgeBaseFile(req.Domain, req.Kid)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Knowledge base file removed successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetCompanyProfile(ctx context.Context, req *v1.GetCompanyProfileReq) (res *v1.GetCompanyProfileRes, err error) {
	res = &v1.GetCompanyProfileRes{}
	res.Data, err = askai.GetCompanyProfile(req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Company profile retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) ModifyCompanyProfile(ctx context.Context, req *v1.ModifyCompanyProfileReq) (res *v1.ModifyCompanyProfileRes, err error) {
	res = &v1.ModifyCompanyProfileRes{}
	err = askai.ModifyCompanyProfile(req.Domain, req.LegalCompanyName, req.Website, req.CompanyProfile, req.Email, req.Phone, req.SupportUrl)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Company profile modified successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetStyleConfig(ctx context.Context, req *v1.GetStyleConfigReq) (res *v1.GetStyleConfigRes, err error) {
	res = &v1.GetStyleConfigRes{}
	res.Data, err = askai.GetStyleConfig(req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Style configuration retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) ModifyStyleConfig(ctx context.Context, req *v1.ModifyStyleConfigReq) (res *v1.ModifyStyleConfigRes, err error) {
	res = &v1.ModifyStyleConfigRes{}
	err = askai.ModifyStyleConfig(req.Domain, req.AccentColor, req.TextColor, req.PageBackground, req.ContainerBackground, req.LinkSocialColor, req.LinkFooterColor, req.HeadingFont, req.BodyFont)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Style configuration modified successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetSitemap(ctx context.Context, req *v1.GetSitemapReq) (res *v1.GetSitemapRes, err error) {
	res = &v1.GetSitemapRes{}
	res.Data, err = askai.GetSiteMap(req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Sitemap retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) RemoveSitemapNode(ctx context.Context, req *v1.RemoveSitemapNodeReq) (res *v1.RemoveSitemapNodeRes, err error) {
	res = &v1.RemoveSitemapNodeRes{}
	err = askai.RemoveSiteMapNode(req.Domain, req.UriPath)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Sitemap node removed successfully")
	}
	return res, nil
}

func (c *ControllerV1) AddSitemapNode(ctx context.Context, req *v1.AddSitemapNodeReq) (res *v1.AddSitemapNodeRes, err error) {
	res = &v1.AddSitemapNodeRes{}
	err = askai.AddSiteMapNode(req.Domain, req.Title, req.UriPath)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Sitemap node added successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetFooter(ctx context.Context, req *v1.GetFooterReq) (res *v1.GetFooterRes, err error) {
	res = &v1.GetFooterRes{}
	res.Data, err = askai.GetFooter(req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Footer retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) ModifyFooter(ctx context.Context, req *v1.ModifyFooterReq) (res *v1.ModifyFooterRes, err error) {
	res = &v1.ModifyFooterRes{}
	err = askai.ModifyFooter(req.Domain, req.CopyrightText, req.Disclaimer, "")
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Footer modified successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetPrompt(ctx context.Context, req *v1.GetPromptReq) (res *v1.GetPromptRes, err error) {
	res = &v1.GetPromptRes{}
	res.Data, err = askai.GetPrompt(req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Prompt retrieved successfully")
	}
	return res, nil
}

func (c *ControllerV1) ModifyPrompt(ctx context.Context, req *v1.ModifyPromptReq) (res *v1.ModifyPromptRes, err error) {
	res = &v1.ModifyPromptRes{}
	err = askai.ModifyPrompt(req.Domain, req.Prompt)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Prompt modified successfully")
	}
	return res, nil
}

func (c *ControllerV1) UploadImage(ctx context.Context, req *v1.UploadImageReq) (res *v1.UploadImageRes, err error) {
	res = &v1.UploadImageRes{}
	imageUrl, err := askai.UploadImage(req.Domain, req.Image, req.Filename, req.AltText, req.ImageTag)
	if err != nil {
		res.SetError(err)
	} else {
		res.Data = map[string]string{
			"url": imageUrl,
		}
		res.SetSuccess("Image uploaded successfully")
	}
	return res, nil
}

func (c *ControllerV1) RemoveImage(ctx context.Context, req *v1.RemoveImageReq) (res *v1.RemoveImageRes, err error) {
	res = &v1.RemoveImageRes{}
	err = askai.RemoveImage(req.Domain, req.ImageId)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Image removed successfully")
	}
	return res, nil
}

func (c *ControllerV1) ModifyImage(ctx context.Context, req *v1.ModifyImageReq) (res *v1.ModifyImageRes, err error) {
	res = &v1.ModifyImageRes{}
	err = askai.ModifyImage(req.Domain, req.ImageId, req.AltText, req.ImageTag)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Image modified successfully")
	}
	return res, nil
}

func (c *ControllerV1) GetImages(ctx context.Context, req *v1.GetImagesReq) (res *v1.GetImagesRes, err error) {
	res = &v1.GetImagesRes{}
	res.Data, err = askai.GetImages(req.Domain)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess("Images retrieved successfully")
	}
	return res, nil
}
