package mail_services

import (
	"billionmail-core/internal/consts"
	docker "billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/os/gtimer"
	"strings"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/mail_services/v1"
)

func (c *ControllerV1) FlushPostfixQueue(ctx context.Context, req *v1.FlushPostfixQueueReq) (res *v1.FlushPostfixQueueRes, err error) {
	res = &v1.FlushPostfixQueueRes{}

	if req.Domain == "" {
		dk, dockerErr := docker.NewDockerAPI()
		if dockerErr != nil {
			g.Log().Error(ctx, "Failed to connect to Docker API:", dockerErr)
			res.SetError(gerror.New(public.LangCtx(ctx, "docker api unavailable: {}", dockerErr.Error())))
			return res, nil
		}
		defer dk.Close()
		cmd := []string{"postqueue", "-f"}
		result, err := dk.ExecCommandByName(ctx, consts.SERVICES.Postfix, cmd, "root")
		if err != nil || result == nil || result.ExitCode != 0 {
			g.Log().Error(ctx, "Failed to flush all postfix queue:", err, result)
			res.SetError(gerror.New(public.LangCtx(ctx, "flush all postfix queue failed: {}", err)))
			return res, nil
		}
		_ = public.WriteLog(ctx, public.LogParams{
			Type: consts.LOGTYPE.PostfixQueue,
			Log:  "Flush all postfix queue mail successfully",
		})
		res.SetSuccess(public.LangCtx(ctx, "flush all postfix queue success"))
		return res, nil
	}

	getReq := &v1.GetPostfixQueueListReq{
		Authorization: req.Authorization,
	}
	queueRes, err := c.GetPostfixQueueList(ctx, getReq)
	if err != nil || queueRes == nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "get postfix queue list failed: {}", err)))
		return res, nil
	}

	targetDomain := strings.ToLower(req.Domain)
	queueIDs := make(map[string]struct{})
	for _, item := range queueRes.Data.List {
		parts := strings.Split(item.Sender, "@")
		if len(parts) == 2 && strings.ToLower(parts[1]) == targetDomain {
			queueIDs[item.QueueID] = struct{}{}
		}
	}

	if len(queueIDs) == 0 {
		res.SetSuccess(public.LangCtx(ctx, "no deferred mail found for sender domain"))
		return res, nil
	}

	gtimer.AddOnce(100*time.Millisecond, func() {
		ctx1 := context.Background()
		dk, dockerErr := docker.NewDockerAPI()
		if dockerErr != nil {
			g.Log().Error(ctx, "Failed to connect to Docker API:", dockerErr)
			return
		}
		defer dk.Close()

		for qid := range queueIDs {
			cmd := []string{"postqueue", "-i", qid}
			result, err := dk.ExecCommandByName(ctx1, consts.SERVICES.Postfix, cmd, "root")
			if err != nil || result == nil || result.ExitCode != 0 {
				g.Log().Error(ctx1, "Failed to flush queue id:", qid, err, result)
			} else {
				g.Log().Info(ctx1, "Flushed queue id:", qid)
			}
		}
	})

	// Operation Log
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.PostfixQueue,
		Log:  "Flush postfix queue mail [" + req.Domain + "] successfully",
	})
	res.SetSuccess(public.LangCtx(ctx, "flush postfix queue success"))
	return res, nil
}
