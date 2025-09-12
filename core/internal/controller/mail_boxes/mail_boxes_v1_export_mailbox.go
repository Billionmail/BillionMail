package mail_boxes

import (
	"billionmail-core/api/mail_boxes/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/mail_boxes"
	"billionmail-core/internal/service/public"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"strings"
)

func (c *ControllerV1) ExportMailbox(ctx context.Context, req *v1.ExportMailboxReq) (res *v1.ExportMailboxRes, err error) {
	res = &v1.ExportMailboxRes{}

	if req.FileType == "" {
		req.FileType = "csv"
	}

	var mailboxes []v1.Mailbox

	mailboxes, err = mail_boxes.All(ctx, req.Domain)
	if err != nil {
		return nil, err
	}

	var content, contentType, fileName string
	switch req.FileType {
	case "txt":
		lines := make([]string, 0, len(mailboxes))
		for _, m := range mailboxes {
			lines = append(lines, m.Username)
		}
		content = strings.Join(lines, "\n")
		contentType = "text/plain"
		fileName = "mailboxes.txt"
	case "json":
		data, _ := json.MarshalIndent(mailboxes, "", "  ")
		content = string(data)
		contentType = "application/json"
		fileName = "mailboxes.json"
	case "csv":
		var b strings.Builder
		w := csv.NewWriter(&b)

		_ = w.Write([]string{"username", "full_name", "is_admin", "quota", "local_part", "domain", "active", "password", "password_encode"})
		for _, m := range mailboxes {
			_ = w.Write([]string{
				m.Username,
				m.FullName,
				fmt.Sprintf("%d", m.IsAdmin),
				fmt.Sprintf("%d", m.Quota),
				m.LocalPart,
				m.Domain,
				fmt.Sprintf("%d", m.Active),
				m.Password,
				m.PasswordEncode,
			})
		}
		w.Flush()
		content = b.String()
		contentType = "text/csv"
		fileName = "mailboxes.csv"
	default:
		return nil, gerror.New("Unsupported export type")
	}

	r := g.RequestFromCtx(ctx)
	if r == nil {
		return nil, gerror.New("Unable to obtain the request context")
	}

	g.Log().Debug(ctx, "contentType:", contentType)
	r.Response.Header().Set("Content-Type", "application/octet-stream")
	r.Response.Header().Set("Content-Disposition", "attachment; filename="+fileName)

	r.Response.Write([]byte(content))

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Mailboxes,
		Log:  "Exporting the email box was successful.",
		Data: mailboxes,
	})

	return
}
