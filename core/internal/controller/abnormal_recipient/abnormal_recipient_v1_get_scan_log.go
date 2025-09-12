package abnormal_recipient

import (
	"billionmail-core/api/abnormal_recipient/v1"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"os"
)

func (c *ControllerV1) GetScanLog(ctx context.Context, req *v1.GetScanLogReq) (res *v1.GetScanLogRes, err error) {
	var logDir = public.HostWorkDir + "/logs/core/check_email_valid.txt"

	res = &v1.GetScanLogRes{}
	exists1 := public.FileExists(logDir)
	if !exists1 {
		res.Data = ""
		res.SetSuccess(public.LangCtx(ctx, "Success"))
		return
	}

	content, err := os.ReadFile(logDir)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Error occurred while reading the scan log: {}", err.Error())))
		return res, nil
	}

	res.Data = string(content)
	res.SetSuccess(public.LangCtx(ctx, "Success"))
	return
}
