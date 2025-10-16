package abnormal_recipient

import (
	"billionmail-core/api/abnormal_recipient/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/abnormal_recipient"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
)

func (c *ControllerV1) DeleteAbnormalRecipient(ctx context.Context, req *v1.DeleteAbnormalRecipientReq) (res *v1.DeleteAbnormalRecipientRes, err error) {
	res = &v1.DeleteAbnormalRecipientRes{}
	abnormalRecipient, _ := abnormal_recipient.GetAbnormalRecipient(ctx, req.Id)
	err = abnormal_recipient.Delete(ctx, req.Id)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to remove exception recipient: {}", err.Error())))
		return
	}
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.AbnormalRecipient,
		Log:  "Delete abnormal recipient :" + abnormalRecipient.Recipient + " successfully",
		Data: abnormalRecipient,
	})

	res.SetSuccess(public.LangCtx(ctx, "The exception recipient was removed successfully"))
	return
}
