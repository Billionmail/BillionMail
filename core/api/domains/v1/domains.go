package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

// DNSRecord defines the DNS record entity
type DNSRecord struct {
	Type  string `json:"type"`
	Host  string `json:"host"`
	Value string `json:"value"`
	Valid bool   `json:"valid"`
}

type DNSRecords struct {
	SPF   DNSRecord `json:"spf"          dc:"SPF record"`
	DKIM  DNSRecord `json:"dkim"         dc:"DKIM record"`
	DMARC DNSRecord `json:"dmarc"         dc:"DMARC record"`
	MX    DNSRecord `json:"mx"   dc:"MX record"`
	A     DNSRecord `json:"a"    dc:"A record"`
	PTR   DNSRecord `json:"ptr"        dc:"PTR record"`
}

type CertInfo struct {
	Subject   string   `json:"subject" dc:"Primary domain"`
	Issuer    string   `json:"issuer" dc:"Certificate brand information"`
	NotBefore string   `json:"not_before" dc:"Validity start time"`
	NotAfter  string   `json:"not_after" dc:"Validity end time"`
	DNSNames  []string `json:"dns" dc:"Optional domain list"`
	Endtime   int      `json:"endtime" dc:"Expiration time, timestamp"`
	KeyPem    string   `json:"key_pem" dc:"Key pem file"`
	CertPem   string   `json:"cert_pem" dc:"Certificate pem file"`
}

// Domain defines the domain entity
type Domain struct {
	Domain       string     `json:"domain"        dc:"Domain name"`
	ARecord      string     `json:"a_record"      dc:"A record"`
	Mailboxes    int        `json:"mailboxes"     dc:"Number of mailboxes created"`
	MailboxQuota int64      `json:"mailbox_quota" dc:"Default mailbox space size"`
	Quota        int64      `json:"quota"         dc:"Domain quota"`
	RateLimit    int        `json:"rate_limit"    dc:"Rate limit for sending emails per second"`
	CreateTime   int64      `json:"create_time"   dc:"Creation time"`
	Active       int        `json:"active"        dc:"Status: 1-enabled, 0-disabled"`
	DNSRecords   DNSRecords `json:"dns_records" dc:"DNS records"`
	CertInfo     CertInfo   `json:"cert_info" dc:"Certificate information"`
	Catchall     string     `json:"email"      dc:"Cache all DNS records, used for domain verification"`
	Default      int        `json:"default"      dc:"Default sender domain, 1-yes, 0-no"`
	Urls         []string   `json:"urls" dc:"Additional URLs associated with the domain"`
	HasBrandInfo int        `json:"hasbrandinfo"        dc:"Brand information : 1-exist, 0-not exist"`
	// 补充专属ip
	MultiIPDomains *MultiIPDomain `json:"multi_ip_domains" dc:"Multiple IP domains"`
}

type AddDomainReq struct {
	g.Meta        `path:"/domains/create" tags:"Domain" method:"post" sm:"Add domain" in:"body"`
	Authorization string   `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string   `json:"domain" v:"required|domain" dc:"Domain"`
	Hostname      string   `json:"hostname" v:"domain" dc:"Hostname, used for A record"`
	Mailboxes     int      `json:"mailboxes" v:"min:1" dc:"Mailboxes" d:"50"`
	MailboxQuota  int      `json:"mailboxQuota" v:"min:1" dc:"MailboxQuota" d:"5242880"`
	Quota         int      `json:"quota" v:"required" dc:"Quota" d:"10485760"`
	RateLimit     int      `json:"rateLimit" v:"min:1" dc:"RateLimit" d:"12"`
	Catchall      string   `json:"email" v:"email" dc:"Catch all email address, used for domain verification"`
	Urls          []string `json:"urls" dc:"Additional URLs associated with the domain"`
	HasBrandInfo  int      `json:"hasbrandinfo"        dc:"Brand information : 1-exist, 0-not exist"`
	OutboundIp   string   `json:"outbound_ip" v:"ipv4" dc:"Exclusive IP address for the domain, used for sending emails"`
}

type AddDomainRes struct {
	api_v1.StandardRes
}

type UpdateDomainReq struct {
	g.Meta        `path:"/domains/update" tags:"Domain" method:"post" sm:"Update domain" in:"body"`
	Authorization string   `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string   `json:"domain" v:"required|domain" dc:"Domain"`
	Hostname      string   `json:"hostname" v:"domain" dc:"Hostname, used for A record"`
	Mailboxes     int      `json:"mailboxes" v:"min:1" dc:"Mailboxes" d:"50"`
	MailboxQuota  int      `json:"mailboxQuota" v:"min:1" dc:"MailboxQuota" d:"5242880"`
	Quota         int      `json:"quota" dc:"Quota" d:"10485760"`
	RateLimit     int      `json:"rateLimit" v:"min:1" dc:"RateLimit" d:"12"`
	Active        int      `json:"active" dc:"Active" d:"1"`
	Catchall      string   `json:"email" v:"email" dc:"Catch all email address, used for domain verification"`
	Urls          []string `json:"urls" dc:"Additional URLs associated with the domain"`
	HasBrandInfo  int      `json:"hasbrandinfo"        dc:"Brand information : 1-exist, 0-not exist"`
	OutboundIp   string   `json:"outbound_ip" v:"ipv4" dc:"Exclusive IP address for the domain, used for sending emails"`
}

type UpdateDomainRes struct {
	api_v1.StandardRes
}

type UpdateDomainBrandinfoReq struct {
	g.Meta        `path:"/domains/update_brandinfo" tags:"Domain" method:"post" sm:"Update domain brandinfo" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`
	HasBrandInfo  int    `json:"hasbrandinfo"        dc:"Brand information : 1-exist, 0-not exist"`
}

type UpdateDomainBrandinfoRes struct {
	api_v1.StandardRes
}

type DeleteDomainReq struct {
	g.Meta        `path:"/domains/delete" tags:"Domain" method:"post" sm:"Delete domain" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`
}

type DeleteDomainRes struct {
	api_v1.StandardRes
}
type MultiIPDomain struct {
	ID             int    `json:"id"`
	Domain         string `json:"domain"`
	OutboundIP     string `json:"outbound_ip"`
	NetworkName    string `json:"network_name"`
	Subnet         string `json:"subnet"`
	PostfixIP      string `json:"postfix_ip"`
	Aliases        string `json:"aliases"`
	SMTPServerName string `json:"smtp_server_name"`
	Active         int    `json:"active"`
	CreateTime     int    `json:"create_time"`
	UpdateTime     int    `json:"update_time"`
	Status         string `json:"status"`
}

type GetDomainReq struct {
	g.Meta        `path:"/domains/list" tags:"Domain" method:"get" sm:"Get domain" in:"query"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Keyword       string `json:"keyword" dc:"Keyword"`
	Page          int    `json:"page" dc:"Page" d:"1"`
	PageSize      int    `json:"page_size" dc:"Page size" d:"20"`
}

type GetDomainRes struct {
	api_v1.StandardRes
	Data struct {
		Total int      `json:"total"`
		List  []Domain `json:"list"`
	} `json:"data"`
}

type GetDomainAllReq struct {
	g.Meta        `path:"/domains/all" tags:"Domain" method:"get" sm:"Get all domains" in:"query"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
}

type GetDomainAllRes struct {
	api_v1.StandardRes
	Data []Domain `json:"data"`
}

type FreshDNSRecordsReq struct {
	g.Meta        `path:"/domains/fresh_dns_records" tags:"Domain" method:"post" sm:"Refresh DNS records" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`
}

type FreshDNSRecordsRes struct {
	api_v1.StandardRes
	Data DNSRecords `json:"data" dc:"DNS records"`
}

type SetSSLReq struct {
	g.Meta        `path:"/domains/set_ssl" tags:"Domain" method:"post" sm:"Set SSL" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`
	Certificate   string `json:"certificate" v:"required" dc:"Certificate"`
	Key           string `json:"key" v:"required" dc:"Key"`
}

type SetSSLRes struct {
	api_v1.StandardRes
}

type GetSSLReq struct {
	g.Meta        `path:"/domains/get_ssl" tags:"Domain" method:"get" sm:"Get SSL" in:"query"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`
}

type GetSSLRes struct {
	api_v1.StandardRes
	Data CertInfo `json:"data" dc:"Certificate information"`
}

type SetDefaultDomainReq struct {
	g.Meta        `path:"/domains/set_default_domain" tags:"Domain" method:"post" sm:"Set default sender domain" in:"body"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required|domain" dc:"Domain"`
}
type SetDefaultDomainRes struct {
	api_v1.StandardRes
}
