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
	"strconv"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"
)

func (c *ControllerV1) ImportMailbox(ctx context.Context, req *v1.ImportMailboxReq) (res *v1.ImportMailboxRes, err error) {
	res = &v1.ImportMailboxRes{}

	// default  CSV
	if req.FileType == "" {
		req.FileType = "csv"
	}

	//// 1. base64
	//raw, err := base64.StdEncoding.DecodeString(req.FileData)
	//if err != nil {
	//	res.SetError(gerror.New(public.LangCtx(ctx, "文件内容解码失败")))
	//	return res, nil
	//}
	//content := string(raw)

	content := req.FileData

	var mailboxes []v1.Mailbox
	switch req.FileType {
	case "json":
		if err := json.Unmarshal([]byte(content), &mailboxes); err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "JSON parsing failed")))
			return res, nil
		}
	case "csv":
		r := csv.NewReader(strings.NewReader(content))
		records, err := r.ReadAll()
		if err != nil || len(records) < 2 {
			res.SetError(gerror.New(public.LangCtx(ctx, "CSV parsing failed")))
			return res, nil
		}
		header := records[0]
		for _, row := range records[1:] {
			m := v1.Mailbox{}
			for i, col := range header {
				if i >= len(row) {
					continue
				}
				switch col {
				case "username":
					m.Username = row[i]
				case "full_name":
					m.FullName = row[i]
				case "is_admin":
					m.IsAdmin = parseInt(row[i])
				case "quota":
					m.Quota = int64(parseInt(row[i]))
				case "local_part":
					m.LocalPart = row[i]
				case "domain":
					m.Domain = row[i]
				case "active":
					m.Active = parseInt(row[i])
				case "password":
					m.Password = row[i]
				case "password_encode":
					m.PasswordEncode = row[i]
				}
			}
			mailboxes = append(mailboxes, m)
		}
	case "txt":
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			mailboxes = append(mailboxes, v1.Mailbox{Username: line})
		}
	default:
		res.SetError(gerror.New(public.LangCtx(ctx, "Unsupported file type")))
		return res, nil
	}

	if len(mailboxes) == 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to parse valid email data")))
		return res, nil
	}

	for i := range mailboxes {
		// If FullName is empty, use LocalPart instead
		if mailboxes[i].FullName == "" && mailboxes[i].LocalPart != "" {
			mailboxes[i].FullName = mailboxes[i].LocalPart
		}

		if mailboxes[i].LocalPart == "" && mailboxes[i].Username != "" {
			if parts := strings.Split(mailboxes[i].Username, "@"); len(parts) == 2 {
				mailboxes[i].LocalPart = parts[0]
				mailboxes[i].Domain = parts[1]
			}
		}

		if mailboxes[i].Domain == "" && mailboxes[i].Username != "" {
			if parts := strings.Split(mailboxes[i].Username, "@"); len(parts) == 2 {
				mailboxes[i].Domain = parts[1]
			}
		}

		if mailboxes[i].Password == "" {
			mailboxes[i].Password = "123456"
		}

		if mailboxes[i].IsAdmin == 0 {
			mailboxes[i].IsAdmin = 0
		}
		if mailboxes[i].Quota == 0 {
			mailboxes[i].Quota = 1000
		}
		if mailboxes[i].Active == 0 {
			mailboxes[i].Active = 1
		}
	}

	var failed []string
	var successCount int
	for _, m := range mailboxes {

		if err := mail_boxes.AddImport(ctx, &m); err != nil {
			failed = append(failed, m.Username)
			continue
		}
		successCount++
	}

	importResult := map[string]interface{}{
		"total":       len(mailboxes),
		"success":     successCount,
		"failed":      len(failed),
		"failed_list": failed,
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Mailboxes,
		Log:  fmt.Sprintf("Import of email account was successful. Total: %d, Success: %d, Failed: %d", len(mailboxes), successCount, len(failed)),
		Data: importResult,
	})

	if len(failed) > 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "The import is complete, but {} email addresses failed to be imported", len(failed))))
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Import completed. A total of {} email addresses were imported.", successCount))
	}

	return res, nil
}

// String to int conversion
func parseInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
