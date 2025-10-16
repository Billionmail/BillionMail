// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package mail_boxes

import (
	"context"

	"billionmail-core/api/mail_boxes/v1"
)

type IMailBoxesV1 interface {
	AddMailbox(ctx context.Context, req *v1.AddMailboxReq) (res *v1.AddMailboxRes, err error)
	BatchAddMailbox(ctx context.Context, req *v1.BatchAddMailboxReq) (res *v1.BatchAddMailboxRes, err error)
	UpdateMailbox(ctx context.Context, req *v1.UpdateMailboxReq) (res *v1.UpdateMailboxRes, err error)
	DeleteMailbox(ctx context.Context, req *v1.DeleteMailboxReq) (res *v1.DeleteMailboxRes, err error)
	GetMailbox(ctx context.Context, req *v1.GetMailboxReq) (res *v1.GetMailboxRes, err error)
	GetAllMailbox(ctx context.Context, req *v1.GetAllMailboxReq) (res *v1.GetAllMailboxRes, err error)
	GetAllEmail(ctx context.Context, req *v1.GetAllEmailReq) (res *v1.GetAllEmailRes, err error)
	ExportMailbox(ctx context.Context, req *v1.ExportMailboxReq) (res *v1.ExportMailboxRes, err error)
	ImportMailbox(ctx context.Context, req *v1.ImportMailboxReq) (res *v1.ImportMailboxRes, err error)
}
