package operation_log

import (
	"billionmail-core/api/operation_log/v1"
	"billionmail-core/internal/service/public"
	"context"
)

func (c *ControllerV1) GetOperationType(ctx context.Context, req *v1.GetOperationTypeReq) (res *v1.GetOperationTypeRes, err error) {
	res = &v1.GetOperationTypeRes{}

	res.Data = public.LogTypeMap
	res.SetSuccess(public.LangCtx(ctx, "Get operation types successfully"))
	return res, nil
}
