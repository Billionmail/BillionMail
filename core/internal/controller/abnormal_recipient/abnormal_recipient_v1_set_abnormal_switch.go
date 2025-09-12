package abnormal_recipient

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"strconv"

	"billionmail-core/api/abnormal_recipient/v1"
)

func (c *ControllerV1) SetAbnormalSwitch(ctx context.Context, req *v1.SetAbnormalSwitchReq) (res *v1.SetAbnormalSwitchRes, err error) {
	res = &v1.SetAbnormalSwitchRes{}
	oper := strconv.Itoa(req.Oper)

	err = SetAbnormalSwitch(oper)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to set the switch: {}", err.Error())))
		return
	}

	action := "Turn on"
	switch req.Oper {
	case 1:
		action = "Turn on"
	case 0:
		action = "Shut down"
	default:
		action = "Illegal operation"
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.AbnormalRecipient,
		Log:  action + " Automatic scanning of abnormal email accounts",
	})

	res.SetSuccess(public.LangCtx(ctx, "Success"))
	return
}
