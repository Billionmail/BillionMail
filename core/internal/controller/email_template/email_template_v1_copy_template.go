package email_template

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/email_template/v1"
	"billionmail-core/internal/service/email_template"
)

func (c *ControllerV1) CopyTemplate(ctx context.Context, req *v1.CopyTemplateReq) (res *v1.CopyTemplateRes, err error) {
	res = &v1.CopyTemplateRes{}

	template, err := email_template.GetTemplate(ctx, req.Id)
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get template {}", err.Error())))
		return
	}
	if template == nil {
		res.Code = 400
		res.SetError(gerror.New(public.LangCtx(ctx, "Template not found")))
		return
	}

	newName := template.TempName + "_bak"
	_, err = email_template.CreateTemplate(ctx, newName, template.AddType, template.Content, template.Render, req.Chat_id)
	if err != nil {
		res.Code = 500
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to create new template {}", err.Error())))
		return
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Template,
		Log:  "Copy template :" + template.TempName + " to " + newName + " successfully",
		Data: template,
	})

	res.SetSuccess(public.LangCtx(ctx, "Template copied successfully"))
	return
}
