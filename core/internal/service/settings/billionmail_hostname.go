package settings

import (
	v1 "billionmail-core/api/domains/v1"
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/public"
	"os"
	"strings"
)

// Check whether the A record of BILLIONMAIL_HOSTNAME is consistent with the local public network IP and write or delete the tag file
func CheckHostname() {
	hostname := public.MustGetDockerEnv("BILLIONMAIL_HOSTNAME", "")
	flagFile := public.AbsPath("../core/data/billionmail_hostname.txt")
	if hostname == "" || hostname == "mail.example.com" {
		_ = os.Remove(flagFile)
		return
	}

	serverIP, err := public.GetServerIP()

	if err != nil {
		return
	}

	recordType := "A"
	if strings.Contains(serverIP, ":") {
		recordType = "AAAA"
	}

	record := v1.DNSRecord{
		Type:  recordType,
		Host:  hostname,
		Value: serverIP,
	}

	Valid := domains.ValidateARecord(record)
	if Valid {
		_ = os.WriteFile(flagFile, []byte(hostname), 0644)
	}

}
