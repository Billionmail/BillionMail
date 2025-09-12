package abnormal_recipient

import (
	"billionmail-core/api/abnormal_recipient/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/abnormal_recipient"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/os/gtimer"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
	"net"
	"os"
	"strings"
	"time"
)

type DNSRecord struct {
	Type  string `json:"type"`
	Host  string `json:"host"`
	Value string `json:"value"`
	Valid bool   `json:"valid"`
}

func (c *ControllerV1) CheckGroup(ctx context.Context, req *v1.CheckGroupReq) (res *v1.CheckGroupRes, err error) {
	g.Log().Info(ctx, "CheckGroup called with req:", req)
	res = &v1.CheckGroupRes{}
	groupNameValue, err := g.DB().Model("bm_contact_groups").Ctx(ctx).Where("id", req.GroupId).Fields("name").Value()
	if err != nil {
		g.Log().Error(ctx, "Group name query error:", err)
		res.SetError(gerror.New(public.LangCtx(ctx, "The group does not exist.")))
		return
	}

	var contacts []entity.Contact
	err = g.DB().Model("bm_contacts").Where("group_id", req.GroupId).Where("active", 1).Scan(&contacts)
	//g.Log().Info(ctx, "bm_contacts query result, contacts:", contacts, "err:", err)
	if err != nil || len(contacts) == 0 {
		g.Log().Error(ctx, "No contacts found or db error:", err)
		res.SetError(gerror.New(public.LangCtx(ctx, "The contact person within the group is unavailable.")))
		return
	}

	var logDir = public.HostWorkDir + "/logs/core/check_email_valid.txt"
	if err := gfile.PutContents(logDir, ""); err != nil {
		g.Log().Error(ctx, "Failed to create or truncate log file:", err)
	}

	gtimer.AddOnce(1000*time.Millisecond, func() {

		f, err := os.OpenFile(logDir, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			g.Log().Error(ctx, "Failed to truncate log file:", err)
		} else {
			f.Close()
		}

		groupNameInfo := groupNameValue.String()
		emails := make([]string, 0, len(contacts))
		for _, c := range contacts {
			emails = append(emails, c.Email)
		}

		domainMap := make(map[string][]string)
		for _, email := range emails {
			parts := strings.SplitN(email, "@", 2)
			if len(parts) == 2 {
				domainMap[parts[1]] = append(domainMap[parts[1]], email)
			}
		}

		g.Log().Info(ctx, "Start async check group, groupNameInfo:", groupNameInfo)
		nowStr := time.Now().Format("2006-01-02 15:04:05")
		groupName := fmt.Sprintf("Group[%s]", groupNameInfo)
		appendLogLine(logDir, fmt.Sprintf("%s: %s start checking...", nowStr, groupName))
		appendLogLine(logDir, fmt.Sprintf("Total emails to check: %d", len(emails)))
		appendLogLine(logDir, fmt.Sprintf("Total domains to check: %d", len(domainMap)))

		var (
			validEmails   []string
			invalidEmails []string
			totalCount    = len(emails)
			validCount    = 0
			invalidCount  = 0
		)

		for domain, domainEmails := range domainMap {
			date := time.Now().Format("2006-01-02 15:04:05")
			record := DNSRecord{
				Type:  "MX",
				Host:  "@",
				Value: domain,
			}
			//g.Log().Info(ctx, "Checking domain:", domain, "emails:", domainEmails)
			status := ValidateMXRecord(record, domain)
			//g.Log().Info(ctx, "ValidateMXRecord result for domain:", domain, "status:", status)
			if status {
				validEmails = append(validEmails, domainEmails...)
				validCount += len(domainEmails)
				appendLogLine(logDir, fmt.Sprintf("%s: %s -----------------------------  √", date, domain))

			} else {
				invalidEmails = append(invalidEmails, domainEmails...)
				invalidCount += len(domainEmails)
				appendLogLine(logDir, fmt.Sprintf("%s: %s ----------------------------- x  mx logging error", date, domain))
			}
		}

		switch req.Oper {
		case 2: // Add abnormal table
			_ = abnormal_recipient.BatchUpsertAbnormalRecipients(ctx, invalidEmails, 3, "Manual scanning group")
			appendLogLine(logDir, "Adding invalid emails to blocklist...")
		case 3: // Remove from the group
			_, _ = g.DB().Model("bm_contacts").Where("group_id", req.GroupId).WhereIn("email", invalidEmails).Delete()
			appendLogLine(logDir, "Removing invalid emails from group...")
		}
		nowStr = time.Now().Format("2006-01-02 15:04:05")
		appendLogLine(logDir, "---------------------------------------------------------------------------------------")
		appendLogLine(logDir, fmt.Sprintf("Results for [%s]:", groupName))
		appendLogLine(logDir, fmt.Sprintf("Tested: %d", totalCount))
		appendLogLine(logDir, fmt.Sprintf("Normal: %d", validCount))
		appendLogLine(logDir, fmt.Sprintf("Abnormal:  %d", invalidCount))
		appendLogLine(logDir, fmt.Sprintf("Abnormal emails: %s", strings.Join(invalidEmails, ", ")))
		appendLogLine(logDir, "---------------------------------------------------------------------------------------")
		appendLogLine(logDir, fmt.Sprintf("%s:  Check finished", nowStr))
	})

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.AbnormalRecipient,
		Log:  "Manually scan the abnormal email addresses in group :" + groupNameValue.String() + " successfully",
	})

	res.SetSuccess(public.LangCtx(ctx, "The process is currently running in the background. Please check the log."))

	return res, nil
}

func ValidateMXRecord(record DNSRecord, domain string, aRecordHosts ...string) bool {
	g.Log().Info(context.Background(), "ValidateMXRecord called with:", record, domain)
	if strings.ToUpper(record.Type) != "MX" {
		return false
	}

	if record.Host != "@" {
		domain = strings.TrimSuffix(record.Host, ".") + "." + domain
	}

	var mxRecords []*net.MX
	var err error

	for i := 0; i < 3; i++ {
		mxRecords, err = net.LookupMX(domain)
		if err == nil {
			break
		}
		if i < 1 { // 不到2次,重试
			time.Sleep(200 * time.Millisecond)
		}
	}

	if err != nil {
		g.Log().Error(context.Background(), "Failed to query MX records after retries:", err)
		return false
	}

	g.Log().Debug(context.Background(), "Query MX records success", mxRecords)

	aRecordHosts = append([]string{record.Value}, aRecordHosts...)

	if len(mxRecords) > 0 {
		return true
	}

	return false
}

func appendLogLine(filePath, line string) {
	defer func() {
		if r := recover(); r != nil {
			g.Log().Error(context.Background(), "panic in appendLogLine:", r)
		}
	}()
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		g.Log().Error(context.Background(), "Failed to open log file:", err)
		return
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	if err != nil {
		g.Log().Error(context.Background(), "Failed to write log line:", err)
	}
}
