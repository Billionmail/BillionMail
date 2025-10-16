package multi_ip_domain

import (
	v1 "billionmail-core/api/domains/v1"
	docker "billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/util/gconv"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type MultiIPDomainService struct {
	applyLocker *sync.Mutex
}

var MultiIPDomainServiceInstance = &MultiIPDomainService{
	applyLocker: &sync.Mutex{},
}

// GetConfigs Get all configurations and their status
func (s *MultiIPDomainService) GetConfigs(ctx context.Context) ([]v1.MultiIPDomain, error) {
	var dbConfigs []v1.MultiIPDomain
	err := g.DB().Model("bm_multi_ip_domain").
		Where("active", 1).
		OrderAsc("id").
		Scan(&dbConfigs)
	return dbConfigs, err
}

// AddConfig Add configuration
func (s *MultiIPDomainService) AddConfig(ctx context.Context, domain, outboundIP string) error {
	if err := s.validateInput(domain, outboundIP); err != nil {
		return err
	}

	if ok, err := s.ValidateDNSRecords(ctx, domain, outboundIP); err != nil && !ok {
		return gerror.Wrap(err, "DNS validation failed")
	}

	return g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		_, err := s.generateNetworkConfig(ctx, tx, domain, outboundIP)
		if err != nil {
			return err
		}
		return nil
	})
}

// generateNetworkConfig Generate network configuration
func (s *MultiIPDomainService) generateNetworkConfig(ctx context.Context, tx gdb.TX, domain, outboundIP string) (int64, error) {

	timestamp := time.Now().Format("20060102150405")
	// master.cf:  smtp_server_name
	smtpServerName := fmt.Sprintf("smtp_bind_ip_%s_%s", strings.ReplaceAll(outboundIP, ".", "_"), timestamp)

	//  docker-compose.yml:  network_name  	 aliases
	networkName := "billionmail-net-" + timestamp
	aliasesStr := "aliases-" + strings.ReplaceAll(domain, ".", "-")

	// Query used subnets
	var usedSubnets []string
	subnetArray, err := tx.Model("bm_multi_ip_domain").
		Where("active >= 0").
		Array("subnet")

	if err != nil {
		return 0, gerror.Wrap(err, "failed to query used subnets")
	}

	// Convert to string array
	usedSubnets = make([]string, 0, len(subnetArray))
	for _, subnet := range subnetArray {
		if subnetStr := gconv.String(subnet); subnetStr != "" {
			usedSubnets = append(usedSubnets, subnetStr)
		}
	}

	usedSubnetMap := make(map[string]bool)
	for _, subnet := range usedSubnets {
		if subnet != "" {
			usedSubnetMap[subnet] = true
		}
	}

	// Start from 172.66.2.0/24, find the first unused subnet
	var subnet string
	var postfixIP string

	for i := 2; i <= 254; i++ {
		candidateSubnet := fmt.Sprintf("172.66.%d.0/24", i)
		candidatePostfixIP := fmt.Sprintf("172.66.%d.100", i)

		if !usedSubnetMap[candidateSubnet] {
			subnet = candidateSubnet
			postfixIP = candidatePostfixIP
			g.Log().Debugf(ctx, "Assigned new subnet: %s (tried %dth subnet)", subnet, i-1)
			break
		} else {
			g.Log().Debugf(ctx, "Subnet %s is already used, try next", candidateSubnet)
		}
	}

	if subnet == "" {
		return 0, gerror.New("No available subnet, maximum number of multi-IP domain configurations supported by the system has been reached (254)")
	}

	cur_time := time.Now().Unix()

	result, err := tx.Model("bm_multi_ip_domain").Data(g.Map{
		"domain":           domain,
		"outbound_ip":      outboundIP,
		"network_name":     networkName,
		"subnet":           subnet,
		"postfix_ip":       postfixIP,
		"aliases":          aliasesStr,
		"smtp_server_name": smtpServerName,
		"active":           1,
		"create_time":      cur_time,
		"update_time":      cur_time,
		"status":           "pending",
	}).Insert()
	if err != nil {
		return 0, gerror.Wrap(err, "database insertion failed")
	}

	configID, _ := result.LastInsertId()
	return configID, nil
}

// DeleteConfig Delete configuration  Delete main configuration and mapping table
func (s *MultiIPDomainService) DeleteConfig(ctx context.Context, domain string) error {
	return g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		var config []v1.MultiIPDomain
		err := g.DB().Model("bm_multi_ip_domain").
			Where("domain", domain).
			Scan(&config)
		if err != nil {
			return err
		}

		if len(config) == 0 {
			//return gerror.New("configuration does not exist")
			return nil
		}

		_, err = tx.Model("bm_multi_ip_domain").Where("domain", domain).Delete()
		if err != nil {
			return gerror.New("failed to delete configuration")
		}
		// Delete mapping bm_domain_smtp_transport   smtp_transport corresponding to domain (atype, domain, smtp_name)
		_, err = tx.Model("bm_domain_smtp_transport").Where("domain", domain).Where("atype", "dedicated_ip").Delete()
		if err != nil {
			return gerror.Wrap(err, "failed to delete domain mapping table")
		}
		return nil
	})
}

// validateInput Validate input
func (s *MultiIPDomainService) validateInput(domain, outboundIP string) error {

	if !isValidDomain(domain) {
		return gerror.New("invalid domain format")
	}
	if !isValidIP(outboundIP) {
		return gerror.New("invalid IP address format")
	}
	return nil
}

// isValidDomain Validate domain format
func isValidDomain(domain string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	return re.MatchString(domain)
}

// isValidIP Validate IP address format
func isValidIP(ip string) bool {
	re := regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)
	return re.MatchString(ip)
}

// ValidateDNSRecords Validate domain A record and SPF record
func (s *MultiIPDomainService) ValidateDNSRecords(ctx context.Context, domain, outboundIP string) (bool, error) {
	formattedDomain := public.FormatMX(domain)

	// 1. Validate A record (required)
	ips, err := net.LookupIP(formattedDomain)
	if err != nil {
		return false, gerror.Newf("failed to query A record for domain '%s': %v. Please ensure the domain is correctly resolved.", domain, err)
	}

	foundA := false
	for _, ip := range ips {
		if ip.To4() != nil && ip.String() == outboundIP {
			foundA = true
			break
		}
	}
	if !foundA {
		return false, gerror.Newf("A record validation failed: The resolution result of domain '%s' does not contain the specified outbound IP '%s'", domain, outboundIP)
	}

	// 2. Validate SPF record (recommended)
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return true, gerror.Newf("failed to query TXT record for domain '%s': %v", domain, err)
	}

	spfRecord := ""
	for _, record := range txtRecords {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=spf1") {
			spfRecord = record
			break
		}
	}

	if spfRecord == "" {
		return true, gerror.Newf("SPF record not found for domain '%s'", domain)
	}

	// Normalize SPF record
	spf := strings.ToLower(strings.TrimSpace(spfRecord))
	if strings.HasPrefix(spf, `"`) && strings.HasSuffix(spf, `"`) {
		spf = spf[1 : len(spf)-1]
	}
	spf = strings.ToLower(spf)

	// Must start with v=spf1
	if !strings.HasPrefix(spf, "v=spf1") {
		return true, gerror.Newf("SPF record is malformed: does not start with 'v=spf1': %s", spfRecord)
	}

	// Must end with ~all or -all
	if !strings.HasSuffix(spf, "~all") && !strings.HasSuffix(spf, "-all") {
		return true, gerror.Newf("SPF record should end with '~all' or '-all' for proper policy enforcement: %s", spfRecord)
	}

	// Check if authorized: ip4, a, or include
	ip4Mech := "ip4:" + outboundIP
	hasIP4 := strings.Contains(spf, ip4Mech)

	hasA := strings.Contains(spf, " a ") || // 中间
		strings.Contains(spf, " a\t") || // tab 分隔
		strings.HasPrefix(spf, "a ") || // 开头
		strings.HasPrefix(spf, "a\t") ||
		strings.Contains(spf, " a:") || // a:domain
		strings.Contains(spf, " a/") // a/24

	hasInclude := strings.Contains(spf, " include:"+domain) ||
		strings.Contains(spf, " include:"+domain+".") ||
		strings.Contains(spf, " include:"+formattedDomain) ||
		strings.HasPrefix(spf, "include:"+domain) ||
		strings.HasPrefix(spf, "include:"+domain+".")

	if hasIP4 || hasA || hasInclude {
		g.Log().Debugf(ctx, "SPF record validation passed: domain='%s', spf='%s'", domain, spfRecord)
		return true, nil
	}

	// No matching mechanism found
	suggestion := gerror.Newf(
		"It is recommended to add 'a', 'ip4:%s', or 'include:%s' in the SPF record to ensure proper authorization of this IP for sending emails.",
		outboundIP, domain,
	)
	return true, suggestion

}

// ApplyConfigs Apply all pending configurations
func (s *MultiIPDomainService) ApplyConfigs(ctx context.Context) (appliedConfigs, failedConfigs []map[string]interface{}, warnings []string, err error) {

	s.applyLocker.Lock()
	defer s.applyLocker.Unlock()

	var allActiveConfigs []map[string]interface{}

	records, err := g.DB().Model("bm_multi_ip_domain").Where("active = 1").OrderAsc("id").All()
	if err != nil {
		return nil, nil, nil, gerror.Wrap(err, "query failed")
	}

	allActiveConfigs = make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		configMap := record.Map()
		if configMap != nil {
			allActiveConfigs = append(allActiveConfigs, configMap)
		}
	}

	if len(allActiveConfigs) == 0 {
		return nil, nil, nil, nil
	}

	// Get IDs from allActiveConfigs
	appliedIDs := make([]int, 0, len(allActiveConfigs))
	toappliedIDs := make([]int, 0, len(allActiveConfigs))
	for _, config := range allActiveConfigs {
		appliedIDs = append(appliedIDs, gconv.Int(config["id"]))
		if config["status"] != "applied" {
			toappliedIDs = append(toappliedIDs, gconv.Int(config["id"]))
		}
	}

	// If the state is already "applied", then do not change it to "applying".
	if err = s.updateStatusByIDs(ctx, toappliedIDs, "applying"); err != nil {
		return nil, nil, nil, gerror.Wrap(err, "failed to update configuration status to 'applying'")
	}

	// Initialize configuration manager
	manager, err := NewConfigManager(ctx)
	if err != nil {
		s.updateStatusByIDs(ctx, appliedIDs, "failed")
		return nil, nil, nil, err
	}

	// Apply configurations
	if err := manager.ApplyConfigsWithRollback(ctx, allActiveConfigs); err != nil {
		s.updateStatusByIDs(ctx, appliedIDs, "failed")
		return nil, nil, nil, err
	}

	// Update status of all related configurations to 'applied'
	//if err := s.updateStatusByIDs(ctx, appliedIDs, "applied"); err != nil {
	//	warnings = append(warnings, "Error occurred while updating database status, but configuration files have taken effect.")
	//}

	return allActiveConfigs, nil, warnings, nil
}

// getPendingConfigIDs Get all configuration IDs whose status is not 'applied'
func (s *MultiIPDomainService) getPendingConfigIDs(ctx context.Context) ([]int, error) {
	var ids []int
	err := g.DB().Model("bm_multi_ip_domain").Where("status != ?", "applied").Fields("id").Scan(&ids)
	return ids, err
}

// updateStatusByIDs
func (s *MultiIPDomainService) updateStatusByIDs(ctx context.Context, ids []int, status string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := g.DB().Model("bm_multi_ip_domain").
		Data(g.Map{
			"status": status,
		}).
		WhereIn("id", ids).
		Update()
	return err
}

// ---------------- core  update iptable ------------------------

type SubnetIP struct {
	Subnet     string `json:"subnet"`
	OutboundIP string `json:"outbound_ip"`
}

// ReapplyAllIptablesRules Reapply all iptables rules
func ReapplyAllIptablesRules(ctx context.Context) {

	var configs []SubnetIP
	err := g.DB().Model("bm_multi_ip_domain").
		Where("active = ?", 1).
		Fields("subnet, outbound_ip").
		Scan(&configs)

	if err != nil {

		return
	}

	if len(configs) == 0 {
		return
	}

	dk, dockerErr := docker.NewDockerAPI()
	if dockerErr != nil {
		g.Log().Error(ctx, "Failed to connect to Docker API:", dockerErr)
		return
	}
	defer dk.Close()

	// Delete old rules
	if err := deleteOldRules(ctx, dk); err != nil {
		g.Log().Error(ctx, "Failed to delete old rules:", err)
	}

	// Add new rules
	if err := addNewRules(ctx, dk, configs); err != nil {
		g.Log().Error(ctx, "Failed to add new rules:", err)
	}

	g.Log().Info(ctx, "iptables rules update completed")
}

func addNewRules(ctx context.Context, dk *docker.DockerAPI, configs []SubnetIP) error {
	addedCount := 0

	for _, config := range configs {
		subnet := config.Subnet
		outboundIP := config.OutboundIP

		// Construct iptables SNAT rule
		cmdStr := fmt.Sprintf(
			`chroot /host_root /sbin/iptables -t nat -I POSTROUTING -s %s -j SNAT --to-source %s -m comment --comment "billionmail-outbound"`,
			subnet, outboundIP,
		)

		cmd := []string{"/bin/sh", "-c", cmdStr}
		result, err := dk.ExecHostCommand(ctx, cmd)
		if err != nil || result.ExitCode != 0 {
			// g.Log().Errorf(ctx, "Failed to add SNAT rule [%s -> %s]: %s", subnet, outboundIP, result.Output)
			continue
		}

		//g.Log().Infof(ctx, "Successfully added SNAT rule: %s → %s", subnet, outboundIP)
		addedCount++
	}

	g.Log().Infof(ctx, "Added %d SNAT rules in total", addedCount)
	return nil
}

// Delete all SNAT rules with the "billionmail-outbound" comment
func deleteOldRules(ctx context.Context, dk *docker.DockerAPI) error {

	// List rules in POSTROUTING chain with line numbers
	listCmd := []string{
		"/bin/sh", "-c",
		`chroot /host_root /sbin/iptables -t nat -L POSTROUTING -n --line-numbers`,
	}
	result, err := dk.ExecHostCommand(ctx, listCmd)
	if err != nil || result.ExitCode != 0 {

		return err
	}

	var ruleNumbers []int
	lines := strings.Split(result.Output, "\n")
	comment := "billionmail-outbound"

	// Scan all lines to find matching rules
	for _, line := range lines {
		if strings.Contains(line, comment) {

			fields := strings.Fields(line)
			if len(fields) > 0 {
				firstField := fields[0]

				//   "q1" -> "1", "D6" -> "6"
				numStr := ""
				for _, char := range firstField {
					if char >= '0' && char <= '9' {
						numStr += string(char)
					}
				}

				if numStr != "" {
					if num, err := strconv.Atoi(numStr); err == nil {
						ruleNumbers = append(ruleNumbers, num)

					} else {
						g.Log().Error(ctx, "Failed to parse line number:", firstField, "Error:", err)
					}
				} else {
					g.Log().Error(ctx, "First field does not contain digits:", firstField, "Line content:", line)
				}
			} else {
				g.Log().Error(ctx, "Line format is abnormal, cannot split fields:", line)
			}
		}
	}

	if len(ruleNumbers) == 0 {

		return nil
	}

	// Delete in reverse order (delete from largest to smallest to avoid line number changes affecting deletion)
	sort.Sort(sort.Reverse(sort.IntSlice(ruleNumbers)))
	deletedCount := 0

	for _, num := range ruleNumbers {
		deleteCmd := []string{
			"/bin/sh", "-c",
			fmt.Sprintf(`chroot /host_root /sbin/iptables -t nat -D POSTROUTING %d`, num),
		}
		result, err := dk.ExecHostCommand(ctx, deleteCmd)
		if err != nil || result.ExitCode != 0 {
			g.Log().Error(ctx, "Failed to delete rule - Line number:", num, "Error message:", result.Output)

		} else {
			deletedCount++
		}
	}

	return nil
}
