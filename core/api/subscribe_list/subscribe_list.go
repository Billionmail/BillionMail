// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package subscribe_list

import (
	"context"

	"billionmail-core/api/subscribe_list/v1"
)

type ISubscribeListV1 interface {
	SubscribeSubmit(ctx context.Context, req *v1.SubscribeSubmitReq) (res *v1.SubscribeSubmitRes, err error)
	SubscribeConfirm(ctx context.Context, req *v1.SubscribeConfirmReq) (res *v1.SubscribeConfirmRes, err error)
}
