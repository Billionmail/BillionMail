package domains

import (
	"billionmail-core/internal/model"
	"billionmail-core/internal/service/mail_service"
	"billionmail-core/internal/service/public"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/miekg/dns"
)

var (
	CONF_BLACKLISTS = []string{
		"bl.spamcop.net",
		"dnsbl.sorbs.net",
		"multi.surbl.org",
		"http.dnsbl.sorbs.net",
		"misc.dnsbl.sorbs.net",
		"socks.dnsbl.sorbs.net",
		"web.dnsbl.sorbs.net",
		"rbl.spamlab.com",
		"cbl.anti-spam.org.cn",
		"httpbl.abuse.ch",
		"virbl.bit.nl",
		"dsn.rfc-ignorant.org",
		"opm.tornevall.org",
		"multi.surbl.org",
		"relays.mail-abuse.org",
		"rbl-plus.mail-abuse.org",
		"rbl.interserver.net",
		"dul.dnsbl.sorbs.net",
		"smtp.dnsbl.sorbs.net",
		"spam.dnsbl.sorbs.net",
		"zombie.dnsbl.sorbs.net",
		"drone.abuse.ch",
		"rbl.suresupport.com",
		"spamguard.leadmon.net",
		"netblock.pedantic.org",
		"blackholes.mail-abuse.org",
		"dnsbl.dronebl.org",
		"query.senderbase.org",
		"csi.cloudmark.com",
		"0spam-killlist.fusionzero.com",
		"access.redhawk.org",
		"all.rbl.jp",
		"all.spam-rbl.fr",
		"all.spamrats.com",
		"aspews.ext.sorbs.net",
		"b.barracudacentral.org",
		"backscatter.spameatingmonkey.net",
		"badnets.spameatingmonkey.net",
		"bb.barracudacentral.org",
		"bl.drmx.org",
		"bl.konstant.no",
		"bl.nszones.com",
		"bl.spamcannibal.org",
		"bl.spameatingmonkey.net",
		"bl.spamstinks.com",
		"black.junkemailfilter.com",
		"blackholes.five-ten-sg.com",
		"blacklist.sci.kun.nl",
		"blacklist.woody.ch",
		"bogons.cymru.com",
		"bsb.empty.us",
		"bsb.spamlookup.net",
		"cart00ney.surriel.com",
		"cbl.abuseat.org",
		"cbl.anti-spam.org.cn",
		"cblless.anti-spam.org.cn",
		"cblplus.anti-spam.org.cn",
		"cdl.anti-spam.org.cn",
		"cidr.bl.mcafee.com",
		"combined.rbl.msrbl.net",
		"db.wpbl.info",
		"dev.null.dk",
		"dialups.visi.com",
		"dnsbl-0.uceprotect.net",
		"dnsbl-1.uceprotect.net",
		"dnsbl-2.uceprotect.net",
		"dnsbl-3.uceprotect.net",
		"dnsbl.anticaptcha.net",
		"dnsbl.aspnet.hu",
		"dnsbl.inps.de",
		"dnsbl.justspam.org",
		"dnsbl.kempt.net",
		"dnsbl.madavi.de",
		"dnsbl.rizon.net",
		"dnsbl.rv-soft.info",
		"dnsbl.rymsho.ru",
		"dnsbl.zapbl.net",
		"dnsrbl.swinog.ch",
		"dul.pacifier.net",
		"dyn.nszones.com",
		"dyna.spamrats.com",
		"fnrbl.fast.net",
		"fresh.spameatingmonkey.net",
		"hostkarma.junkemailfilter.com",
		"images.rbl.msrbl.net",
		"ips.backscatterer.org",
		"ix.dnsbl.manitu.net",
		"korea.services.net",
		"l2.bbfh.ext.sorbs.net",
		"l3.bbfh.ext.sorbs.net",
		"l4.bbfh.ext.sorbs.net",
		"list.bbfh.org",
		"list.blogspambl.com",
		"mail-abuse.blacklist.jippg.org",
		"netbl.spameatingmonkey.net",
		"netscan.rbl.blockedservers.com",
		"no-more-funn.moensted.dk",
		"noptr.spamrats.com",
		"orvedb.aupads.org",
		"pbl.spamhaus.org",
		"phishing.rbl.msrbl.net",
		"pofon.foobar.hu",
		"psbl.surriel.com",
		"rbl.abuse.ro",
		"rbl.blockedservers.com",
		"rbl.dns-servicios.com",
		"rbl.efnet.org",
		"rbl.efnetrbl.org",
		"rbl.iprange.net",
		"rbl.schulte.org",
		"rbl.talkactive.net",
		"rbl2.triumf.ca",
		"rsbl.aupads.org",
		"sbl-xbl.spamhaus.org",
		"sbl.nszones.com",
		"sbl.spamhaus.org",
		"short.rbl.jp",
		"spam.dnsbl.anonmails.de",
		"spam.pedantic.org",
		"spam.rbl.blockedservers.com",
		"spam.rbl.msrbl.net",
		"spam.spamrats.com",
		"spamrbl.imp.ch",
		"spamsources.fabel.dk",
		"st.technovision.dk",
		"tor.dan.me.uk",
		"tor.dnsbl.sectoor.de",
		"tor.efnet.org",
		"torexit.dan.me.uk",
		"truncate.gbudb.net",
		"ubl.unsubscore.com",
		"uribl.spameatingmonkey.net",
		"urired.spameatingmonkey.net",
		"virbl.dnsbl.bit.nl",
		"virus.rbl.jp",
		"virus.rbl.msrbl.net",
		"vote.drbl.caravan.ru",
		"vote.drbl.gremlin.ru",
		"web.rbl.msrbl.net",
		"work.drbl.caravan.ru",
		"work.drbl.gremlin.ru",
		"wormrbl.imp.ch",
		"xbl.spamhaus.org",
		"zen.spamhaus.org",
	}

	//SPECIAL_IP_RESPONSES = map[string]string{
	//	"127.0.0.2": "SBL - Spamhaus SBL Data",
	//	"127.0.0.3": "SBL - Spamhaus SBL CSS Data",
	//	"127.0.0.4": "XBL - CBL Data",
	//	"127.0.0.5": "XBL - NJABL Data",
	//	"127.0.0.6": "XBL - CBL Data",
	//	"127.0.1.2": "PBL - Spamhaus PBL Data",
	//	"127.0.1.4": "PBL - ISP Maintained",
	//	"127.0.1.5": "PBL - ISP Maintained",
	//	"127.0.1.6": "PBL - ISP Maintained",
	//}

	SKIP_IP_RESPONSES = map[string]string{
		"127.255.255.254": "Passed",
		"127.255.255.255": "Passed",
		"127.0.0.1":       "Passed",
		"127.0.1.1":       "Passed",
		"127.0.0.7":       "Passed",
	}

	DOMAIN_SCAN_LOG_PATH = public.AbsPath("../core/data")
)

// The blacklist for detecting scheduled task invocations
func CheckDomainsBlacklist(ctx context.Context) {

	var autoScanEnabled bool
	err := public.OptionsMgrInstance.GetOption(ctx, "blacklist_auto_scan_enabled", &autoScanEnabled)
	if err != nil {
		autoScanEnabled = true
	}
	if !autoScanEnabled {
		return
	}

	domains, err := All(ctx)
	if err != nil {
		return
	}

	if len(domains) == 0 {
		return
	}

	var waitDuration time.Duration
	if len(domains) <= 8 {
		waitDuration = 3 * time.Hour
	} else {
		hoursPerDomain := 24.0 / float64(len(domains))
		waitDuration = time.Duration(hoursPerDomain * float64(time.Hour))
	}

	for i, domain := range domains {

		if domain.ARecord == "" {
			continue
		}

		ip, err := ResolveA(domain.ARecord, nil)
		if err != nil {
			//g.Log().Errorf(ctx, "Failed to parse the A record of domain name %s: %v. Skipping the check.", domain.ARecord, err)
			continue
		}

		_, err = IsDomainBlacklisted(ctx, ip, domain.ARecord, nil)
		if err != nil {
			continue
		}

		if i < len(domains)-1 {
			//g.Log().Infof(ctx, "Wait for %.0f minutes and then check the next domain name...", waitDuration.Minutes())
			time.Sleep(waitDuration)
		}
	}

	//g.Log().Infof(ctx, "The blacklist check task has been completed. A total of %d domain names were checked.", len(domains))
}

// IsDomainBlacklisted
func IsDomainBlacklisted(ctx context.Context, ip, domain string, dns_servers []string) (*model.BlacklistCheckResult, error) {
	result := &model.BlacklistCheckResult{
		Domain:    domain,
		IP:        ip,
		Time:      gtime.Now().Timestamp(),
		Tested:    len(CONF_BLACKLISTS),
		BlackList: []model.BlacklistDetail{},
	}

	reversedIP := ReverseIP(ip) // "1.2.3.4" -> "4.3.2.1"

	//g.Log().Infof(ctx, "开始对域名进行黑名单检查: %s, IP: %s (reversed: %s)", domain, ip, reversedIP)

	domainCheckLog := fmt.Sprintf("%s/%s_blcheck.txt", DOMAIN_SCAN_LOG_PATH, domain)
	_ = gfile.PutContents(domainCheckLog, "")
	date := gtime.Now().Format("Y-m-d H:i:s")
	checkLog := fmt.Sprintf("%s:  Start checking... \n", date)
	_ = gfile.PutContentsAppend(domainCheckLog, checkLog)

	for _, bl := range CONF_BLACKLISTS {
		times := gtime.Now().Timestamp()
		date := gtime.Now().Format("Y-m-d H:i:s")
		query := fmt.Sprintf("%s.%s", reversedIP, bl)

		//g.Log().Infof(ctx, "检查黑名单: %s for domain: %s", bl, domain)
		//g.Log().Infof(ctx, "检查黑名单query: %s", query)

		resp, err := ResolveA(query, dns_servers)

		//g.Log().Infof(ctx, "黑名单检查结果: %s, err: %v", resp, err)

		if err != nil {
			checkLog = fmt.Sprintf("%s: %s -----------------------------  √\n", date, bl)
			_ = gfile.PutContentsAppend(domainCheckLog, checkLog)
			result.Passed++
			//g.Log().Infof(ctx, "黑名单检查通过√: %s ", resp)
		} else if strings.HasPrefix(resp, "127.") {

			if _, ok := SKIP_IP_RESPONSES[resp]; ok {
				result.Passed++
				checkLog = fmt.Sprintf("%s: %s -----------------------------  √ (%s)\n", date, bl, resp)
				_ = gfile.PutContentsAppend(domainCheckLog, checkLog)
				//g.Log().Infof(ctx, "黑名单检查通过√ (跳过): %s ", resp)
			} else if strings.HasPrefix(resp, "127.0.0.") {
				result.Blacklisted++
				checkLog = fmt.Sprintf("%s: %s ----------------------------- x   blacklisted (%s)\n", date, bl, resp)
				_ = gfile.PutContentsAppend(domainCheckLog, checkLog)

				result.BlackList = append(result.BlackList, model.BlacklistDetail{
					Blacklist: bl,
					Time:      times,
					Response:  resp,
				})
				//g.Log().Warningf(ctx, "黑名单检查未通过x : %s ", resp)
			} else {
				result.Passed++
				checkLog = fmt.Sprintf("%s: %s ----------------------------- √ (%s)\n", date, bl, resp)
				_ = gfile.PutContentsAppend(domainCheckLog, checkLog)
				//g.Log().Infof(ctx, "黑名单检查通过!! √ : %s ", resp)
			}
		} else {
			checkLog = fmt.Sprintf("%s: %s ----------------------------- Invalid\n", date, bl)
			_ = gfile.PutContentsAppend(domainCheckLog, checkLog)
			result.Invalid++
		}
	}

	date = gtime.Now().Format("Y-m-d H:i:s")
	checkLog = fmt.Sprintf("---------------------------------------------------------------------------------------  \n"+
		"Results for %s: \n"+
		"Ip: %s \n"+
		"Tested: %d \n"+
		"Passed: %d \n"+
		"Invalid: %d \n"+
		"Blacklisted: %d \n"+
		"---------------------------------------------------------------------------------------   \n"+
		"%s:  Check finished\n", domain, ip, len(CONF_BLACKLISTS), result.Passed, result.Invalid, result.Blacklisted, date)
	_ = gfile.PutContentsAppend(domainCheckLog, checkLog)

	addBlacklist(domain, result)

	// Check the alerts and push them
	if result.Blacklisted > 0 {

		go sendBlacklistAlert(ctx, ip, domain, result)
	}

	return result, nil
}

// ResolveA
func ResolveA(domain string, servers []string) (string, error) {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	var server string
	if len(servers) > 0 {
		server = servers[0] + ":53"
	} else {
		server = "8.8.8.8:53" // fallback
	}

	for i := 0; i < 2; i++ {
		r, _, err := c.Exchange(m, server)
		if err == nil && len(r.Answer) > 0 {
			if a, ok := r.Answer[0].(*dns.A); ok {
				return a.A.String(), nil
			}
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("resolve failed")
}

// addBlacklist
func addBlacklist(domain string, blcheck_info *model.BlacklistCheckResult) {

	path := public.AbsPath("../core/data/blcheck_count.json")
	data := make(map[string]*model.BlacklistCheckResult)
	if gfile.Exists(path) {
		content := gfile.GetContents(path)
		_ = json.Unmarshal([]byte(content), &data)
	}
	data[domain] = blcheck_info
	json_data, _ := json.Marshal(data)
	_ = gfile.PutContents(path, string(json_data))
}

// ReverseIP
func ReverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

// GetBlacklistResult
func GetBlacklistResult(domain string) *model.BlacklistCheckResult {
	path := public.AbsPath("../core/data/blcheck_count.json")
	if !gfile.Exists(path) {
		return nil
	}

	content := gfile.GetContents(path)
	if content == "" {
		return nil
	}

	data := make(map[string]*model.BlacklistCheckResult)
	err := json.Unmarshal([]byte(content), &data)
	if err != nil {
		return nil
	}

	if result, ok := data[domain]; ok {
		return result
	}

	return nil
}

// GetBlacklistLogPath
func GetBlacklistLogPath(domain string) string {
	logPath := fmt.Sprintf("%s/%s_blcheck.txt", DOMAIN_SCAN_LOG_PATH, domain)
	return logPath
}

func sendBlacklistAlert(ctx context.Context, ip, domain string, result *model.BlacklistCheckResult) {

	var alertEnabled bool
	err := public.OptionsMgrInstance.GetOption(ctx, "blacklist_alert_enabled", &alertEnabled)
	if err != nil || !alertEnabled {
		//g.Log().Infof(ctx, "Blacklist alert is disabled, skipping alert for domain: %s", domain)
		return
	}

	alertSettings, err := loadBlacklistAlertSettingsForAlert()
	if err != nil || alertSettings == nil {
		g.Log().Errorf(ctx, "Failed to load alert settings, skipping alert for domain: %s, error: %v", domain, err)
		return
	}

	if alertSettings.SenderEmail == "" || alertSettings.SMTPServer == "" || len(alertSettings.RecipientList) == 0 {
		g.Log().Errorf(ctx, "Alert settings incomplete, skipping alert for domain: %s", domain)
		return
	}

	subject := fmt.Sprintf("⚠️ Blacklist Alert - %s", domain)
	body := buildBlacklistAlertEmailHTML(ip, domain, result)

	err = sendAlertEmail(ctx, alertSettings, subject, body)
	if err != nil {
		g.Log().Errorf(ctx, "Failed to send blacklist alert for domain: %s, error: %v", domain, err)
		return
	}

	g.Log().Infof(ctx, "✅ Blacklist alert sent successfully for domain: %s to %d recipients", domain, len(alertSettings.RecipientList))
}

type BlacklistAlertSettings struct {
	Name          string   `json:"name"`
	SenderEmail   string   `json:"sender_email"`
	SMTPPassword  string   `json:"smtp_password"`
	SMTPServer    string   `json:"smtp_server"`
	SMTPPort      int      `json:"smtp_port"`
	RecipientList []string `json:"recipient_list"`
}

func loadBlacklistAlertSettingsForAlert() (*BlacklistAlertSettings, error) {
	alertSettingsFile := public.AbsPath("../core/data/blacklist_alert_settings.json")

	if !gfile.Exists(alertSettingsFile) {
		return nil, fmt.Errorf("alert settings file not found")
	}

	content := gfile.GetContents(alertSettingsFile)
	if content == "" {
		return nil, fmt.Errorf("alert settings file is empty")
	}

	var settings BlacklistAlertSettings
	err := json.Unmarshal([]byte(content), &settings)
	if err != nil {
		return nil, fmt.Errorf("failed to parse alert settings: %v", err)
	}

	return &settings, nil
}

func sendAlertEmail(ctx context.Context, settings *BlacklistAlertSettings, subject, body string) error {

	sender := mail_service.NewEmailSender()
	sender.Host = settings.SMTPServer
	sender.Port = fmt.Sprintf("%d", settings.SMTPPort)
	sender.Email = settings.SenderEmail
	sender.UserName = settings.SenderEmail
	sender.Password = settings.SMTPPassword

	err := sender.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %v", err)
	}
	defer sender.Close()

	var failedRecipients []string
	for _, recipient := range settings.RecipientList {

		message := mail_service.NewMessage(subject, body)
		message.SetRealName(settings.Name)
		messageId := sender.GenerateMessageID()
		message.SetMessageID(messageId)

		err = sender.Send(message, []string{recipient})
		if err != nil {
			g.Log().Errorf(ctx, "Failed to send alert email to %s: %v", recipient, err)
			failedRecipients = append(failedRecipients, recipient)
		} else {
			g.Log().Infof(ctx, "Alert email sent successfully to %s", recipient)
		}
	}

	if len(failedRecipients) > 0 {
		return fmt.Errorf("failed to send alert email to %d recipient(s): %v", len(failedRecipients), failedRecipients)
	}

	return nil
}

func buildBlacklistAlertEmailHTML(ip, domain string, result *model.BlacklistCheckResult) string {

	var blacklistItems string
	for i, bl := range result.BlackList {
		blacklistItems += fmt.Sprintf("                <li><strong>%d. %s</strong> (Response: %s)</li>\n",
			i+1, bl.Blacklist, bl.Response)
	}

	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<title>Blacklist Detection Alert</title>
		<style>
			p {
				margin: 0;
			}
			body {
				background: #f5f5f5;
				margin: 0;
				padding: 20px;
				font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
			}
			.container {
				max-width: 620px;
				margin: 40px auto;
				background: white;
				border-radius: 12px;
				box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
				overflow: hidden;
			}
			.header {
				text-align: center;
				padding: 40px 30px 30px;
				background: linear-gradient(135deg, #fef3f2, #fdf2f8);
			}
			.alert-icon {
				width: 80px;
				height: 80px;
				background: linear-gradient(135deg, #dc2626, #b91c1c);
				border-radius: 50%%;
				display: flex;
				align-items: center;
				justify-content: center;
				margin: 0 auto;
				box-shadow: 0 4px 15px rgba(220, 38, 38, 0.3);
			}
			.content {
				padding: 32px 40px;
			}
			.content h2 {
				margin-top: 0;
				margin-bottom: 24px;
				color: #1f2937;
				font-size: 24px;
				font-weight: 600;
				text-align: center;
			}
			.content h3 {
				margin-top: 0;
				margin-bottom: 16px;
				color: #dc2626;
				font-size: 18px;
				font-weight: 600;
			}
			.content p {
				margin-top: 12px;
				color: #6b7280;
				font-size: 13px;
				line-height: 1.5;
			}
			.alert-box {
				background: #fef3f2;
				border-left: 4px solid #dc2626;
				padding: 16px 20px;
				margin: 24px 0;
				border-radius: 4px;
			}
			.domain-info {
				display: grid;
				grid-template-columns: 1fr 1fr 1fr;
				gap: 20px;
				margin: 20px 0;
				padding: 20px;
				background: #f9fafb;
				border-radius: 8px;
			}
			.label {
				font-weight: 600;
				color: #4b5563;
				display: block;
				margin-bottom: 4px;
				font-size: 13px;
			}
			.value {
				color: #1f2937;
				font-weight: 500;
				font-size: 15px;
			}
			.severity-high {
				color: #dc2626;
				font-weight: 600;
			}
			.results-grid {
				display: grid;
				grid-template-columns: repeat(4, 1fr);
				gap: 12px;
				margin: 20px 0;
			}
			.result-item {
				text-align: center;
				padding: 16px 8px;
				border-radius: 8px;
				background: #f9fafb;
			}
			.result-value {
				font-size: 24px;
				font-weight: 700;
				margin-bottom: 4px;
			}
			.result-label {
				font-size: 12px;
				color: #6b7280;
			}
			.result-passed {
				color: #10b981;
			}
			.result-blacklisted {
				color: #dc2626;
			}
			.blacklisted-item {
				background: #fef3f2;
				padding: 12px 16px;
				margin: 8px 0;
				border-radius: 6px;
				border-left: 3px solid #dc2626;
			}
			.action-box {
				background: #f9fafb;
				border-radius: 8px;
				padding: 20px;
				margin: 24px 0;
			}
			.action-list {
				margin: 16px 0;
				padding-left: 20px;
			}
			.action-list li {
				margin-bottom: 8px;
				color: #374151;
				line-height: 1.5;
				font-size: 13px;
			}
			.footer {
				text-align: center;
				padding: 20px 30px 30px;
				color: #9ca3af;
				font-size: 12px;
				background: #f9fafb;
				border-top: 1px solid #f3f4f6;
			}
			.footer a {
				color: #9ca3af;
				text-decoration: underline;
			}
			.footer a:hover {
				color: #6b7280;
			}
			@media only screen and (max-width: 700px) {
				.container {
					max-width: 95%%;
				}
				.content {
					padding: 25px 20px;
				}
				.domain-info,
				.results-grid {
					grid-template-columns: 1fr;
				}
				.button-container {
					flex-direction: column;
				}
			}
		</style>
	</head>
	<body>
		<div class="container">
			<div class="header">
				<div class="alert-icon">
					<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white" width="40" height="40">
						<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z" />
					</svg>
				</div>
			</div>
			<div class="content">
				<h2>Blacklist Detection Alert</h2>

				<div class="alert-box">Your domain has been detected on email blacklists!</div>

				<h3>Domain Information</h3>
				<div class="domain-info">
					<div class="info-item">
						<span class="label">Domain</span>
						<span class="value" id="domain-value"> %s </span>
					</div>
					<div class="info-item">
						<span class="label">IP Address</span>
						<span class="value" id="ip-value"> %s </span>
					</div>
					<div class="info-item">
						<span class="label">Detection Time</span>
						<span class="value" id="detection-time-value"> %s </span>
					</div>
				</div>

				<h3>Detection Results</h3>
				<div class="results-grid">
					<div class="result-item">
						<div class="result-value" id="total-tested-value"> %d </div>
						<div class="result-label">Total Blacklists</div>
					</div>
					<div class="result-item">
						<div class="result-value result-passed" id="passed-value"> %d </div>
						<div class="result-label">Passed</div>
					</div>
					<div class="result-item">
						<div class="result-value" id="invalid-value"> %d </div>
						<div class="result-label">Invalid</div>
					</div>
					<div class="result-item">
						<div class="result-value result-blacklisted" id="blacklisted-value"> %d </div>
						<div class="result-label">Blacklisted</div>
					</div>
				</div>

				<h3>Blacklisting Providers</h3>
				<div id="blacklisted-list">
					<div class="blacklisted-item">%s</div>

				</div>

				<div class="action-box">
					<h3>Recommended Actions</h3>
					<p>To protect your domain reputation, please perform the following actions immediately:</p>
					<ul class="action-list">
						<li>Review recent email content and sending frequency</li>
						<li>Ensure there is no unauthorized sending activity</li>
						<li>Contact the relevant blacklist providers to understand delisting procedures</li>
						<li>Verify domain configuration and SPF/DKIM/DMARC records</li>
					</ul>
				</div>
			</div>

			<div class="footer">
				<div>
					<span>Powered by </span>
					<a href="https://www.billionmail.com/" target="_blank">BillionMail</a>
				</div>
			</div>
		</div>
	</body>
</html>

`, domain, ip, time.Unix(result.Time, 0).Format("2006-01-02 15:04:05"),
		result.Tested, result.Passed, result.Invalid, result.Blacklisted,
		blacklistItems,
	)
}
