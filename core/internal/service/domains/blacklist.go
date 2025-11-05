package domains

import (
	"billionmail-core/internal/model"
	"billionmail-core/internal/service/public"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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

	//// 有黑名单,检查告警并推送
	//if result.Blacklisted > 0 {
	//	args := &public.SendMailDataArgs{
	//		Keyword: "mail_domain_black",
	//		Domain:  domain,
	//	}
	//	var blacklists []string
	//	for _, b := range result.BlackList {
	//		blacklists = append(blacklists, b.Blacklist)
	//	}
	//	body := []string{
	//		fmt.Sprintf(">Send content: Your IP [%s] is on the email blacklist.", ip),
	//		fmt.Sprintf(">Results for %s.", domain),
	//		fmt.Sprintf(">Blacklisted: %v.", blacklists),
	//	}
	//	args.Body = body
	//	public.SendMailData(ctx, args)
	//}

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
