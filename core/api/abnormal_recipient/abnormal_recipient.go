// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package abnormal_recipient

import (
	"context"

	"billionmail-core/api/abnormal_recipient/v1"
)

type IAbnormalRecipientV1 interface {
	ListAbnormalRecipient(ctx context.Context, req *v1.ListAbnormalRecipientReq) (res *v1.ListAbnormalRecipientRes, err error)
	AddAbnormalRecipient(ctx context.Context, req *v1.AddAbnormalRecipientReq) (res *v1.AddAbnormalRecipientRes, err error)
	DeleteAbnormalRecipient(ctx context.Context, req *v1.DeleteAbnormalRecipientReq) (res *v1.DeleteAbnormalRecipientRes, err error)
	CheckGroup(ctx context.Context, req *v1.CheckGroupReq) (res *v1.CheckGroupRes, err error)
	AbnormalSwitch(ctx context.Context, req *v1.AbnormalSwitchReq) (res *v1.AbnormalSwitchRes, err error)
	SetAbnormalSwitch(ctx context.Context, req *v1.SetAbnormalSwitchReq) (res *v1.SetAbnormalSwitchRes, err error)
	ClearabnormalRecipient(ctx context.Context, req *v1.ClearabnormalRecipientReq) (res *v1.ClearabnormalRecipientRes, err error)
	GetScanLog(ctx context.Context, req *v1.GetScanLogReq) (res *v1.GetScanLogRes, err error)
}
