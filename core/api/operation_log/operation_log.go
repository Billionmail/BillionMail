// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package operation_log

import (
	"context"

	"billionmail-core/api/operation_log/v1"
)

type IOperationLogV1 interface {
	GetOperationLog(ctx context.Context, req *v1.GetOperationLogReq) (res *v1.GetOperationLogRes, err error)
	GetOperationType(ctx context.Context, req *v1.GetOperationTypeReq) (res *v1.GetOperationTypeRes, err error)
	GetOutputLog(ctx context.Context, req *v1.GetOutputLogReq) (res *v1.GetOutputLogRes, err error)
	GetLatestOutputLog(ctx context.Context, req *v1.GetLatestOutputLogReq) (res *v1.GetLatestOutputLogRes, err error)
}
