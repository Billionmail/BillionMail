package mail_services

import (
	docker "billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"context"
	"strings"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"

	"billionmail-core/api/mail_services/v1"
	"billionmail-core/internal/consts"
)

func (c *ControllerV1) GetPostfixQueueList(ctx context.Context, req *v1.GetPostfixQueueListReq) (res *v1.GetPostfixQueueListRes, err error) {
	res = &v1.GetPostfixQueueListRes{}
	dk, dockerErr := docker.NewDockerAPI()
	if dockerErr != nil {
		g.Log().Error(ctx, "Failed to connect to Docker API:", dockerErr)
		res.SetError(gerror.New(public.LangCtx(ctx, "docker api unavailable: {}", dockerErr.Error())))
		return res, nil
	}
	defer dk.Close()
	var cmd []string
	if req.Domain != "" {
		cmd = []string{"sh", "-c", "postqueue -j | grep -i '" + req.Domain + "'"}
	} else {
		cmd = []string{"postqueue", "-j"}
	}
	result, err := dk.ExecCommandByName(ctx, consts.SERVICES.Postfix, cmd, "root")
	if err != nil {
		g.Log().Error(ctx, "Failed to execute command in container :", err, "command:", strings.Join(cmd, " "))
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to execute command in container: {}", err.Error())))
		return res, nil
	}

	if result == nil {
		g.Log().Error(ctx, "The result of the command is empty:", "command:", strings.Join(cmd, " "))
		res.SetError(gerror.New(public.LangCtx(ctx, "The result of the command is empty: {}", strings.Join(cmd, " "))))
		return res, nil
	}
	if result.ExitCode != 0 {
		g.Log().Error(ctx, "The command execution returns a nonzero status:", result.ExitCode, "output:", result.Output, "command:", strings.Join(cmd, " "))
		res.SetError(gerror.New(public.LangCtx(ctx, "Command execution failed, exit code: {}, output: {}", result.ExitCode, result.Output)))
		return res, nil
	}

	lines := strings.Split(result.Output, "\n")
	list := make([]v1.QueueMailItem, 0)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var item struct {
			QueueName    string `json:"queue_name"`
			QueueID      string `json:"queue_id"`
			ArrivalTime  int64  `json:"arrival_time"`
			MessageSize  int    `json:"message_size"`
			ForcedExpire bool   `json:"forced_expire"`
			Sender       string `json:"sender"`
			Recipients   []struct {
				Address     string `json:"address"`
				DelayReason string `json:"delay_reason,omitempty"`
			} `json:"recipients"`
		}
		if err := gjson.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		if item.QueueName != "deferred" {
			continue
		}
		for _, r := range item.Recipients {
			list = append(list, v1.QueueMailItem{
				QueueID:      item.QueueID,
				Sender:       item.Sender,
				Recipients:   nil,
				ArrivalTime:  item.ArrivalTime,
				DelayReason:  r.DelayReason,
				MessageSize:  item.MessageSize,
				QueueName:    item.QueueName,
				ForcedExpire: item.ForcedExpire,
				Recipient:    r.Address,
			})
		}
	}
	res.Data.List = list
	res.Data.Total = len(list)
	res.SetSuccess(public.LangCtx(ctx, "get postfix queue list success"))
	return res, nil
}
