package mail_boxes

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"billionmail-core/internal/service/mail_service"
	"github.com/gogf/gf/v2/frame/g"
)

// -----------------------------
// Check the email domain and mailbox quota usage and send alerts. Scheduled task
// Rule: quota_active = 1 and quota > 0, usage rate >= 90% or 95% triggers an alert (priority is given to the higher threshold)
// De-duplication: Do not repeat alerts for the same object and the same threshold within 24 hours
// -----------------------------

const (
	quotaAlertThreshold90 = 90
	quotaAlertThreshold95 = 95
	quotaAlertHoldHours   = 24
)

type quotaAlertTarget struct {
	Kind      string  `json:"kind"` // domain/mailbox
	Target    string  `json:"target"`
	Percent   float64 `json:"percent"`
	Used      int64   `json:"used"`
	Quota     int64   `json:"quota"`
	Threshold int     `json:"threshold"`
}

var (
	// key: kind|target|threshold -> lastTime
	quotaAlertCache = sync.Map{} // map[string]time.Time
)

// CheckMailboxesQuotaAlerts 域名/邮箱配额告警
func CheckMailboxesQuotaAlerts(ctx context.Context) {

	domainAlerts := collectDomainQuotaAlerts(ctx)
	mailboxAlerts := collectMailboxQuotaAlerts(ctx)

	if len(domainAlerts) == 0 && len(mailboxAlerts) == 0 {
		return
	}

	all := append(domainAlerts, mailboxAlerts...)
	for _, a := range all {

		if shouldSkipAlert(a) {
			continue
		}

		//recordQuotaAlert(ctx, a)

		markAlertSent(a)

		// send email asynchronously
		go func(alert quotaAlertTarget) {
			if err := sendQuotaAlertEmail(ctx, alert); err != nil {
				g.Log().Warning(ctx, "send quota alert email failed", err)
			}
		}(a)
	}
}

func collectDomainQuotaAlerts(ctx context.Context) []quotaAlertTarget {
	type dRow struct {
		Domain string
		Quota  int64
		Used   int64
	}
	var rows []dRow

	if err := g.DB().Model("domain").
		Fields("domain, quota, COALESCE(current_usage,0) as used").
		Where("quota > 0").
		Scan(&rows); err != nil && err != sql.ErrNoRows {
		g.Log().Warning(ctx, "collect domain quota failed", err)
		return nil
	}
	alerts := make([]quotaAlertTarget, 0)
	for _, r := range rows {
		if r.Quota <= 0 {
			continue
		}
		pct := float64(r.Used) / float64(r.Quota) * 100
		var threshold int
		if pct >= quotaAlertThreshold95 {
			threshold = quotaAlertThreshold95
		} else if pct >= quotaAlertThreshold90 {
			threshold = quotaAlertThreshold90
		} else {
			continue
		}
		alerts = append(alerts, quotaAlertTarget{Kind: "domain", Target: r.Domain, Percent: pct, Used: r.Used, Quota: r.Quota, Threshold: threshold})
	}
	return alerts
}

func collectMailboxQuotaAlerts(ctx context.Context) []quotaAlertTarget {
	type mRow struct {
		Username    string
		Quota       int64
		UsedQuota   int64
		QuotaActive int
	}
	var rows []mRow
	if err := g.DB().Model("mailbox").
		Fields("username, quota, COALESCE(used_quota,0) used_quota, COALESCE(quota_active,1) quota_active").
		Where("active", 1).
		Where("quota_active", 1).
		Where("quota  > ?", 0).
		Scan(&rows); err != nil && err != sql.ErrNoRows {
		g.Log().Warning(ctx, "collect mailbox quota failed", err)
		return nil
	}

	if len(rows) == 0 {
		return nil
	}

	alerts := make([]quotaAlertTarget, 0)
	for _, r := range rows {

		pct := float64(r.UsedQuota) / float64(r.Quota) * 100
		var threshold int
		if pct >= quotaAlertThreshold95 {
			threshold = quotaAlertThreshold95
		} else if pct >= quotaAlertThreshold90 {
			threshold = quotaAlertThreshold90
		} else {
			continue
		}
		alerts = append(alerts, quotaAlertTarget{Kind: "mailbox", Target: r.Username, Percent: pct, Used: r.UsedQuota, Quota: r.Quota, Threshold: threshold})
	}
	return alerts
}

// skip if alerted within 24 hours for the same object and threshold
func shouldSkipAlert(a quotaAlertTarget) bool {
	key := fmt.Sprintf("%s|%s|%d", a.Kind, a.Target, a.Threshold)
	if v, ok := quotaAlertCache.Load(key); ok {
		if ts, ok2 := v.(time.Time); ok2 {
			if time.Since(ts) < quotaAlertHoldHours*time.Hour {
				return true
			}
		}
	}
	return false
}

func markAlertSent(a quotaAlertTarget) {
	key := fmt.Sprintf("%s|%s|%d", a.Kind, a.Target, a.Threshold)
	quotaAlertCache.Store(key, time.Now())
}

//func recordQuotaAlert(ctx context.Context, a quotaAlertTarget) {
//	//data, _ := json.Marshal(a)
//	msg := fmt.Sprintf("Quota alert %s=%s threshold=%d used=%d quota=%d percent=%.2f%%", a.Kind, a.Target, a.Threshold, a.Used, a.Quota, a.Percent)
//}

func sendQuotaAlertEmail(ctx context.Context, a quotaAlertTarget) error {
	domain := ""
	if a.Kind == "mailbox" {
		parts := strings.Split(a.Target, "@")
		if len(parts) == 2 {
			domain = parts[1]
		}
	} else if a.Kind == "domain" {
		domain = a.Target
	}
	if domain == "" {
		d, _ := getDefaultSendDomain()
		domain = d
	}

	fromAddress := fmt.Sprintf("noreply@%s", domain)
	toAddress := fromAddress
	if a.Kind == "mailbox" {
		toAddress = a.Target
	}

	usedStr := formatSize(a.Used)
	quotaStr := formatSize(a.Quota)
	subject := fmt.Sprintf("[Quota %d%% Alert] %s usage %.1f%%", a.Threshold, a.Target, a.Percent)
	if a.Percent >= 100 {
		subject = fmt.Sprintf("[Quota EXCEEDED] %s %.1f%%", a.Target, a.Percent)
	}

	bodyBuilder := &strings.Builder{}
	fmt.Fprintf(bodyBuilder, "Hello,\n\n")
	if a.Kind == "mailbox" {
		fmt.Fprintf(bodyBuilder, "Mailbox: %s\n", a.Target)
	} else {
		fmt.Fprintf(bodyBuilder, "Domain: %s\n", a.Target)
	}
	fmt.Fprintf(bodyBuilder, "Quota: %s\nUsed: %s (%.2f%%)\nThreshold: %d%%\n\n", quotaStr, usedStr, a.Percent, a.Threshold)
	if a.Percent >= 100 {
		bodyBuilder.WriteString("Status: EXCEEDED LIMIT, new mails may be rejected.\n\n")
	} else {
		bodyBuilder.WriteString("Status: Approaching limit.\n\n")
	}
	bodyBuilder.WriteString("Suggested actions:\n - Delete large or old mails\n - Empty Trash/Spam folders\n - Request quota increase if necessary\n\nThis is an automated notification.\n")
	content := bodyBuilder.String()

	sender, err := mail_service.NewEmailSenderWithLocal(fromAddress)
	if err != nil {
		return err
	}
	defer sender.Close()
	msg := mail_service.NewMessage(subject, content)
	msg.SetRealName("Quota Monitor")

	return sender.Send(msg, []string{toAddress})
}

func getDefaultSendDomain() (string, error) {

	var defaultDomain string
	val, err := g.DB().Model("bm_options").Where("name", "default_sender_domain").Value("value")
	if err == nil && val != nil {
		defaultDomain = val.String()
	}

	return defaultDomain, nil
}

func formatSize(v int64) string {
	if v < 1024 {
		return fmt.Sprintf("%dB", v)
	}
	kb := float64(v) / 1024
	if kb < 1024 {
		return fmt.Sprintf("%.2fKB", kb)
	}
	mb := kb / 1024
	if mb < 1024 {
		return fmt.Sprintf("%.2fMB", mb)
	}
	gb := mb / 1024
	return fmt.Sprintf("%.2fGB", gb)
}
