// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package mail_services

import (
	"context"

	"billionmail-core/api/mail_services/v1"
)

type IMailServicesV1 interface {
	GetConfigFile(ctx context.Context, req *v1.GetConfigFileReq) (res *v1.GetConfigFileRes, err error)
	SaveConfigFile(ctx context.Context, req *v1.SaveConfigFileReq) (res *v1.SaveConfigFileRes, err error)
	GetBccList(ctx context.Context, req *v1.GetBccListReq) (res *v1.GetBccListRes, err error)
	AddBcc(ctx context.Context, req *v1.AddBccReq) (res *v1.AddBccRes, err error)
	EditBcc(ctx context.Context, req *v1.EditBccReq) (res *v1.EditBccRes, err error)
	DeleteBcc(ctx context.Context, req *v1.DeleteBccReq) (res *v1.DeleteBccRes, err error)
	GetMailForwardList(ctx context.Context, req *v1.GetMailForwardListReq) (res *v1.GetMailForwardListRes, err error)
	AddMailForward(ctx context.Context, req *v1.AddMailForwardReq) (res *v1.AddMailForwardRes, err error)
	EditMailForward(ctx context.Context, req *v1.EditMailForwardReq) (res *v1.EditMailForwardRes, err error)
	DeleteMailForward(ctx context.Context, req *v1.DeleteMailForwardReq) (res *v1.DeleteMailForwardRes, err error)
	GetPostfixQueueList(ctx context.Context, req *v1.GetPostfixQueueListReq) (res *v1.GetPostfixQueueListRes, err error)
	GetPostfixQueueInfo(ctx context.Context, req *v1.GetPostfixQueueInfoReq) (res *v1.GetPostfixQueueInfoRes, err error)
	DeletePostfixQueueById(ctx context.Context, req *v1.DeletePostfixQueueByIdReq) (res *v1.DeletePostfixQueueByIdRes, err error)
	DeleteAllDeferredQueue(ctx context.Context, req *v1.DeleteAllDeferredQueueReq) (res *v1.DeleteAllDeferredQueueRes, err error)
	FlushPostfixQueue(ctx context.Context, req *v1.FlushPostfixQueueReq) (res *v1.FlushPostfixQueueRes, err error)
	FlushPostfixQueueById(ctx context.Context, req *v1.FlushPostfixQueueByIdReq) (res *v1.FlushPostfixQueueByIdRes, err error)
	SetPostfixConfig(ctx context.Context, req *v1.SetPostfixConfigReq) (res *v1.SetPostfixConfigRes, err error)
	SetAllPostfixConfig(ctx context.Context, req *v1.SetAllPostfixConfigReq) (res *v1.SetAllPostfixConfigRes, err error)
	GetPostfixConfig(ctx context.Context, req *v1.GetPostfixConfigReq) (res *v1.GetPostfixConfigRes, err error)
}
