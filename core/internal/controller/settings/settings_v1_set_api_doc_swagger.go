package settings

import (
	"billionmail-core/api/settings/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/errors/gerror"
	"time"
)

func (c *ControllerV1) SetAPIDocSwagger(ctx context.Context, req *v1.SetAPIDocSwaggerReq) (res *v1.SetAPIDocSwaggerRes, err error) {
	res = &v1.SetAPIDocSwaggerRes{}

	// Track if any configuration was modified
	configModified := false

	// Update API documentation enabled status (controls both API docs and Swagger UI)
	var currentAPIDocEnabled bool
	err = public.OptionsMgrInstance.GetOption(ctx, "API_DOC_ENABLED", &currentAPIDocEnabled)
	if err != nil || currentAPIDocEnabled != req.APIDocEnabled {
		err = public.OptionsMgrInstance.SetOption(ctx, "API_DOC_ENABLED", req.APIDocEnabled)
		if err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to update API documentation setting: {}", err)))
			return res, nil
		}
		configModified = true
	}

	if configModified {
		// Log the operation
		_ = public.WriteLog(ctx, public.LogParams{
			Type: consts.LOGTYPE.Settings,
			Log:  "Updated API documentation and Swagger UI configuration",
			Data: map[string]interface{}{
				"api_doc_enabled": req.APIDocEnabled,
			},
		})

		gtimer.AddOnce(500*time.Millisecond, func() {
			err = public.DockerApiFromCtx(ctx).RestartContainerByName(context.Background(), consts.SERVICES.Core)
			if err != nil {
				return
			}
		})

		res.SetSuccess(public.LangCtx(ctx, "API documentation and Swagger UI configuration updated successfully, service restarted"))
	} else {
		res.SetSuccess(public.LangCtx(ctx, "No configuration changes needed"))
	}

	return res, nil
}
