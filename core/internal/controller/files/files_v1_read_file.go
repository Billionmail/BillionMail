package files

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"billionmail-core/api/files/v1"
)

func (c *ControllerV1) ReadFile(ctx context.Context, req *v1.ReadFileReq) (res *v1.ReadFileRes, err error) {

	return nil, status.Errorf(codes.Unimplemented, "Not yet achieved")
}
