package files

import (
	"billionmail-core/api/files/v1"
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (c *ControllerV1) DownloadFile(ctx context.Context, req *v1.DownloadFileReq) (res *v1.DownloadFileRes, err error) {
	return nil, status.Errorf(codes.Unimplemented, "Not yet achieved")
}
