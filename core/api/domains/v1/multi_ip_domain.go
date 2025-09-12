package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

// ApplyMultiIPDomainConfigReq
type ApplyMultiIPDomainConfigReq struct {
	g.Meta        `path:"/multi_ip_domain/apply" method:"post" summary:"Apply multi-IP domain configuration"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
}

// ApplyMultiIPDomainConfigRes
type ApplyMultiIPDomainConfigRes struct {
	api_v1.StandardRes
	Data struct {
		AppliedConfigs []string `json:"applied_configs" dc:"Applied configurations"`
		FailedConfigs  []string `json:"failed_configs" dc:"Failed configurations"`
		Warnings       []string `json:"warnings" dc:"Warning messages"`
		Command        string   `json:"command" dc:"Utility command"`
		FixCommand     string   `json:"fix_command" dc:"Recovery command"`
	} `json:"data"`
}

// TestMultiIPDomainConfigReq Request to test multi-IP domain configuration
type TestMultiIPDomainConfigReq struct {
	g.Meta        `path:"/multi_ip_domain/test" method:"post" summary:"Test multi-IP domain configuration"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header"`
	Domain        string `json:"domain" v:"required" dc:"Domain name"`
	OutboundIP    string `json:"outbound_ip" v:"required" dc:"Outbound IP"`
}

// TestMultiIPDomainConfigRes Response for testing multi-IP domain configuration
type TestMultiIPDomainConfigRes struct {
	api_v1.StandardRes
}
