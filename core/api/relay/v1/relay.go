package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

// BmRelay
type BmRelay struct {
	Id             int      `json:"id"`
	Remark         string   `json:"remark"`          // Remark, e.g., "AWS SES Japan Region"
	Rtype          string   `json:"rtype"`           // type: gmail, sendgrid, custom, aws, mailgun, local
	RelayHost      string   `json:"relay_host"`      // Relay server address,
	RelayPort      string   `json:"relay_port"`      // Relay server port, e.g., "587"
	AuthUser       string   `json:"auth_user"`       // SMTP authentication username
	AuthPassword   string   `json:"auth_password"`   // SMTP authentication password (consider encrypted storage)
	Ip             string   `json:"ip"`              // IP for reminding users to update SPF record (optional)
	Host           string   `json:"host"`            // Host for reminding users to update SPF record (optional)
	Active         int      `json:"active"`          // Whether this relay configuration is active: 1-enabled, 0-disabled
	CreateTime     int      `json:"create_time"`     // Creation time
	UpdateTime     int      `json:"update_time"`     // Update time
	AuthMethod     string   `json:"auth_method"`     // Authentication method: LOGIN, PLAIN, CRAM-MD5, NONE
	TlsProtocol    string   `json:"tls_protocol"`    // TLS protocol: STARTTLS, SSL/TLS, NONE
	SkipTlsVerify  int      `json:"skip_tls_verify"` // Whether to skip TLS verification: 1-skip, 0-do not skip
	HeloName       string   `json:"helo_name"`       // HELO hostname
	SmtpName       string   `json:"smtp_name"`       // Unique name of the SMTP server
	HeaderJson     string   `json:"header_json"`     // Custom email headers in JSON format
	MaxConcurrency int      `json:"max_concurrency"` // Maximum concurrent connections
	MaxRetries     int      `json:"max_retries"`     // Maximum retry attempts
	MaxIdleTime    string   `json:"max_idle_time"`   // Maximum idle connection time
	MaxWaitTime    string   `json:"max_wait_time"`   // Maximum wait time
	SenderDomains  []string `json:"sender_domains"`  // Array of sender domains associated with this relay config
	//RelayDomains   []*RelayDomainMapping `json:"relay_domains"`   // Domain mapping details
}

//type RelayDomainMapping struct {
//	Id           int    `json:"id"`
//	RelayId      int    `json:"relay_id"`
//	SenderDomain string `json:"sender_domain"`
//	CreateTime   int    `json:"create_time"`
//}

// DNSRecord struct represents a DNS record
type DNSRecord struct {
	Type  string `json:"type"`
	Host  string `json:"host"`
	Value string `json:"value"`
}

// SmtpStatus SMTP connection status
type SmtpStatus struct {
	Status bool   `json:"status"` // Whether the connection is successful
	Msg    string `json:"msg"`    // Status description
	//LastTime int64  `json:"lastTime"` // Last test time (Unix timestamp)
}

// BmRelayWithSPF
type BmRelayWithSPF struct {
	*BmRelay
	SPFRecords []*SPFStatus `json:"spf_records"`
	SmtpStatus SmtpStatus   `json:"smtp_status"`
	CheckSPF   int          `json:"check_spf"` // Whether to check SPF record: 1-check, 0-do not check
}

type SPFStatus struct {
	DNSRecord DNSRecord `json:"dns_record"` // SPF
	Check     int       `json:"check"`      // Verification status (0: Correct, 1: Incorrect/Needs modification)
}

// CreateRelayConfigReq Request to add a relay configuration
type CreateRelayConfigReq struct {
	g.Meta        `path:"/relay/add" method:"post" tags:"Relay Configs" summary:"Create a new relay configuration"`
	Authorization string    `json:"authorization" in:"header" dc:"Authorization" v:"required"`
	Remark        string    `json:"remark" v:"max-length:255" dc:"Remark, e.g., AWS SES Japan Region"`
	Rtype         string    `json:"rtype" v:"max-length:30" dc:"Relay type: gmail, sendgrid, custom, aws, mailgun, local"`
	SenderDomains []string  `json:"sender_domains" v:"required" dc:"Array of sender domains"`
	RelayHost     string    `json:"relay_host" v:"required|max-length:255" dc:"Relay server address"`
	RelayPort     string    `json:"relay_port" v:"required|max-length:10" dc:"Relay server port, e.g., 587"`
	AuthUser      string    `json:"auth_user" v:"required|max-length:255" dc:"SMTP authentication username"`
	AuthPassword  string    `json:"auth_password" v:"required|max-length:255" dc:"SMTP authentication password"`
	IP            string    `json:"ip" v:"max-length:255" dc:"IP for reminding users to update SPF record, e.g., +ip4:23.158.104.237"`
	Host          string    `json:"host" v:"max-length:255" dc:"Host for reminding users to update SPF record, e.g., include:lootk.cn"`
	Active        int       `json:"active" d:"1" v:"in:0,1" dc:"Whether enabled: 1-enabled, 0-disabled (default is 1)"`
	AuthMethod    string    `json:"auth_method" v:"max-length:20" dc:"Authentication method: LOGIN, PLAIN, CRAM-MD5, NONE"`
	TlsProtocol   string    `json:"tls_protocol" v:"max-length:20" dc:"TLS protocol: STARTTLS, SSL/TLS, NONE"`
	SkipTlsVerify int       `json:"skip_tls_verify" v:"in:0,1" dc:"Whether to skip TLS verification: 1-skip, 0-do not skip"`
	HeloName      string    `json:"helo_name" v:"max-length:255" dc:"HELO hostname"`
	SmtpName      string    `json:"smtp_name" v:"max-length:50" dc:"Unique name of the SMTP server"`
	SPFRecord     DNSRecord `json:"spf_record"` // Generated SPF record suggestion
}
type CreateRelayConfigRes struct {
	api_v1.StandardRes
	SPFRecord DNSRecord `json:"spf_record"`
}

// ListRelayConfigsReq Request to get a list of relay configurations
type ListRelayConfigsReq struct {
	g.Meta        `path:"/relay/list" method:"get" tags:"Relay Configs" summary:"Get the list of relay configurations"`
	Authorization string `json:"authorization" in:"header" dc:"Authorization" v:"required"`
	Keyword       string `json:"keyword" dc:"search"`
	Rtype         string `json:"rtype" dc:"gmail, sendgrid, custom, aws, mailgun, local"`
}

type ListRelayConfigsRes struct {
	api_v1.StandardRes
	Data struct {
		Total int               `json:"total" dc:"Total records count"`
		List  []*BmRelayWithSPF `json:"list" dc:"Relay configuration list"`
	} `json:"data"`
}

// UpdateRelayConfigReq Request to update a relay configuration
type UpdateRelayConfigReq struct {
	g.Meta        `path:"/relay/edit" method:"post" tags:"Relay Configs" summary:"Update a relay configuration"`
	Authorization string `json:"authorization" in:"header" dc:"Authorization" v:"required"`
	ID            int    `json:"id" v:"required|min:1" dc:"The ID of the configuration to update"`
	Rtype         string `json:"rtype,omitempty" v:"max-length:30" dc:"rtype: gmail, sendgrid, custom, aws, mailgun, local"`
	Remark        string `json:"remark,omitempty" v:"max-length:255" dc:"Remark, e.g., AWS SES Japan Region"`
	RelayHost     string `json:"relay_host,omitempty" v:"max-length:255" dc:"Relay server address"`
	RelayPort     string `json:"relay_port,omitempty" v:"max-length:10" dc:"Relay server port, e.g., 587"`
	AuthUser      string `json:"auth_user,omitempty" v:"max-length:255" dc:"SMTP authentication username"`
	AuthPassword  string `json:"auth_password,omitempty" v:"max-length:255" dc:"SMTP authentication password (no update if not provided)"`
	IP            string `json:"ip,omitempty" v:"max-length:255" dc:"IP for reminding users to update SPF record, e.g., +ip4:23.158.104.237"`
	Host          string `json:"host,omitempty" v:"max-length:255" dc:"Host for reminding users to update SPF record, e.g., include:lootk.cn"`
	Active        int    `json:"active,omitempty" v:"in:0,1" dc:"Whether enabled: 1-enabled, 0-disabled"`

	SenderDomains []string `json:"sender_domains,omitempty" dc:"Domains to add to this relay configuration"`

	// Advanced options
	AuthMethod    string `json:"auth_method,omitempty" v:"max-length:20" dc:"Authentication method: LOGIN, PLAIN, CRAM-MD5, NONE"`
	SkipTlsVerify int    `json:"skip_tls_verify,omitempty" v:"in:0,1" dc:"Whether to skip TLS verification: 1-skip, 0-do not skip"`
	HeloName      string `json:"helo_name,omitempty" v:"max-length:255" dc:"HELO hostname"`
	SmtpName      string `json:"smtp_name,omitempty" v:"max-length:50" dc:"Unique name of the SMTP server"`
}

type UpdateRelayConfigRes struct {
	api_v1.StandardRes
	SPFRecord DNSRecord `json:"spf_record"`
}

// DeleteRelayConfigReq Request to delete a relay configuration
type DeleteRelayConfigReq struct {
	g.Meta        `path:"/relay/delete" method:"post" tags:"Relay Configs" summary:"Delete a relay configuration"`
	Authorization string `json:"authorization" in:"header" dc:"Authorization" v:"required"`
	ID            int64  `json:"id" v:"required|min:1" dc:"The ID of the configuration to delete"`
}

type DeleteRelayConfigRes struct {
	api_v1.StandardRes
}

// DomainInfo Represents domain information
type DomainInfo struct {
	Domain  string `json:"domain"`
	IsBound bool   `json:"is_bound"`
}

type GetUnboundDomainsReq struct {
	g.Meta        `path:"/relay/get_unbound_domains" method:"get" tags:"Relay Configs" summary:"Get domains without bound relay services"`
	Authorization string `json:"authorization" in:"header" dc:"Authorization" v:"required"`
}

type GetUnboundDomainsRes struct {
	api_v1.StandardRes
	Data []*DomainInfo `json:"data" dc:"List of domain info"`
}

// TestSmtpConnectionReq Test SMTP connection request
type TestSmtpConnectionReq struct {
	g.Meta        `path:"/relay/test_connection" method:"post" tags:"Relay Configs" summary:"Test if the SMTP relay connection is normal"`
	Authorization string `json:"authorization" in:"header" dc:"Authorization" v:"required"`
	RelayHost     string `json:"relay_host" v:"required|max-length:255" dc:"Relay server address"`
	RelayPort     string `json:"relay_port" v:"required|max-length:10" dc:"Relay server port, e.g., 587"`
	AuthUser      string `json:"auth_user" v:"max-length:255" dc:"SMTP authentication username"`
	AuthPassword  string `json:"auth_password" v:"max-length:255" dc:"SMTP authentication password"`
}

// TestSmtpConnectionRes Test SMTP connection response
type TestSmtpConnectionRes struct {
	api_v1.StandardRes
	Data struct {
		ServerInfo      string `json:"server_info" dc:"Server information"`
		TlsStatus       string `json:"tls_status" dc:"TLS status"`
		AuthStatus      string `json:"auth_status" dc:"Authentication status"`
		ConnectionTime  int64  `json:"connection_time" dc:"Connection establishment time (milliseconds)"`
		SupportedAuth   string `json:"supported_auth" dc:"Authentication methods supported by the server"`
		RecommendConfig bool   `json:"recommend_config" dc:"Whether this configuration is recommended"`
	} `json:"data"`
}
