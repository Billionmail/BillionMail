// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package files

import (
	"context"

	"billionmail-core/api/files/v1"
)

type IFilesV1 interface {
	DownloadFile(ctx context.Context, req *v1.DownloadFileReq) (res *v1.DownloadFileRes, err error)
	ReadFile(ctx context.Context, req *v1.ReadFileReq) (res *v1.ReadFileRes, err error)
}
