package relay

import (
	"testing"

	domainsV1 "billionmail-core/api/domains/v1"
	"billionmail-core/internal/service/public"

	"github.com/stretchr/testify/assert"
)

// TestGenerateSPFRecord covers the ip/host inputs documented for the relay API
// (api/relay/v1: `+ip4:23.158.104.237`, `include:lootk.cn`) as well as bare
// addresses and hosts. Each case asserts the exact record handed to the user.
func TestGenerateSPFRecord(t *testing.T) {
	// BillionMail's own SPF suggestion, as stored by domains.FreshRecords.
	const suggested = "v=spf1 +a +mx +ip4:62.146.181.127 -all"

	tests := []struct {
		name     string
		existing string
		ip       string
		host     string
		want     string
	}{
		{
			// The reported symptom: choosing a relay on the domain's own address
			// must not leave the server's address authorised alongside it.
			name:     "bare ip matching an existing ip4 mechanism is not duplicated",
			existing: suggested,
			ip:       "62.146.181.127",
			want:     suggested,
		},
		{
			name:     "qualified bare ip matching an existing mechanism is not duplicated",
			existing: suggested,
			ip:       "+ip4:62.146.181.127",
			want:     suggested,
		},
		{
			name:     "new bare ip is appended before all",
			existing: suggested,
			ip:       "147.93.139.179",
			want:     "v=spf1 +a +mx +ip4:62.146.181.127 +ip4:147.93.139.179 -all",
		},
		{
			name:     "bare ipv6",
			existing: suggested,
			ip:       "2001:db8::1",
			want:     "v=spf1 +a +mx +ip4:62.146.181.127 +ip6:2001:db8::1 -all",
		},
		{
			name:     "bare host becomes an include mechanism",
			existing: suggested,
			host:     "smtp.gmail.com",
			want:     "v=spf1 +a +mx +ip4:62.146.181.127 include:smtp.gmail.com -all",
		},
		{
			name:     "ip already prefixed with ip4: is not prefixed twice",
			existing: suggested,
			ip:       "+ip4:23.158.104.237",
			want:     "v=spf1 +a +mx +ip4:62.146.181.127 +ip4:23.158.104.237 -all",
		},
		{
			name:     "host already prefixed with include: is not prefixed twice",
			existing: suggested,
			host:     "include:lootk.cn",
			want:     "v=spf1 +a +mx +ip4:62.146.181.127 include:lootk.cn -all",
		},
		{
			name:     "documented ip and host together",
			existing: suggested,
			ip:       "+ip4:23.158.104.237",
			host:     "include:lootk.cn",
			want:     "v=spf1 +a +mx +ip4:62.146.181.127 +ip4:23.158.104.237 include:lootk.cn -all",
		},
		{
			name:     "no ip or host leaves the record untouched",
			existing: suggested,
			want:     suggested,
		},
		{
			name:     "missing all mechanism defaults to ~all",
			existing: "v=spf1 +a +mx",
			ip:       "1.2.3.4",
			want:     "v=spf1 +a +mx +ip4:1.2.3.4 ~all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain := "example.com"
			public.SetCache(buildCacheKey(domain, "SPF"), domainsV1.DNSRecord{
				Type:  "TXT",
				Host:  "@",
				Value: tt.existing,
			}, 600)

			assert.Equal(t, tt.want, GenerateSPFRecord(tt.ip, tt.host, domain))
		})
	}
}
