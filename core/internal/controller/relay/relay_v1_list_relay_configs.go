package relay

import (
	"billionmail-core/api/relay/v1"
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/public"
	relay_service "billionmail-core/internal/service/relay"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/os/gcache"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

func (c *ControllerV1) ListRelayConfigs(ctx context.Context, req *v1.ListRelayConfigsReq) (res *v1.ListRelayConfigsRes, err error) {
	res = &v1.ListRelayConfigsRes{}
	res.Data.List = make([]*v1.BmRelayWithSPF, 0)

	model := g.DB().Model("bm_relay_config").Safe()

	if req.Keyword != "" {
		searchKey := "%" + req.Keyword + "%"
		model = model.WhereLike("remark", searchKey).
			WhereOrLike("relay_host", searchKey).
			WhereOrLike("auth_user", searchKey).
			WhereOrLike("smtp_name", searchKey)
	}

	if req.Rtype != "" {
		model = model.Where("rtype", req.Rtype)
	}

	total, err := model.Count()
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to retrieve relay configuration count: {}", err.Error())))
		return res, nil
	}

	var configs []*entity.BmRelayConfig
	err = model.Order("create_time DESC").Scan(&configs)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to retrieve relay configurations: {}", err.Error())))
		return res, nil
	}

	for _, config := range configs {

		relayWithSPF := &v1.BmRelayWithSPF{
			BmRelay: &v1.BmRelay{
				Id:            config.Id,
				Remark:        config.Remark,
				Rtype:         config.Rtype,
				RelayHost:     config.RelayHost,
				RelayPort:     config.RelayPort,
				AuthUser:      config.AuthUser,
				AuthPassword:  "",
				Ip:            config.Ip,
				Host:          config.Host,
				Active:        config.Active,
				CreateTime:    config.CreateTime,
				UpdateTime:    config.UpdateTime,
				AuthMethod:    config.AuthMethod,
				HeloName:      config.HeloName,
				SmtpName:      config.SmtpName,
				SkipTlsVerify: config.SkipTlsVerify,
				SenderDomains: []string{},
			},
			SmtpStatus: v1.SmtpStatus{
				Status: true,
				Msg:    "Connected",
			},
			SPFRecords: make([]*v1.SPFStatus, 0),
		}

		var mappings []*entity.BmRelayDomainMapping
		err = g.DB().Model("bm_relay_domain_mapping").
			Where("relay_id", config.Id).
			Scan(&mappings)

		if err != nil {
			g.Log().Debug(ctx, "Failed to query domain mappings for relay ID", config.Id, ":", err)
		} else {

			for _, mapping := range mappings {

				relayWithSPF.BmRelay.SenderDomains = append(relayWithSPF.BmRelay.SenderDomains, mapping.SenderDomain)
			}
		}

		if len(relayWithSPF.BmRelay.SenderDomains) > 0 {
			var smtpIp string
			var smtpHost string

			if net.ParseIP(relayWithSPF.BmRelay.RelayHost) != nil {
				smtpIp = relayWithSPF.BmRelay.RelayHost
				smtpHost = ""
			} else {
				smtpIp = ""
				smtpHost = relayWithSPF.BmRelay.RelayHost
			}

			for _, domain := range relayWithSPF.BmRelay.SenderDomains {

				spfValue := relay_service.GenerateSPFRecord(smtpIp, smtpHost, domain)

				checkStatus := 0

				if config.SmtpName == "Custom SMTP Relay" {
					spfCurValue, _ := GetRealSPFRecord(ctx, domain)
					if spfCurValue != "" {

						if !containsSPF(spfCurValue, smtpIp, smtpHost) {
							checkStatus = 1
						}
					} else {
						checkStatus = 1
					}
				}

				spfStatus := &v1.SPFStatus{
					DNSRecord: v1.DNSRecord{
						Type:  "TXT",
						Host:  domain,
						Value: spfValue,
					},
					Check: checkStatus,
				}
				relayWithSPF.SPFRecords = append(relayWithSPF.SPFRecords, spfStatus)

			}

			hasInvalidSPF := false
			for _, spfStatus := range relayWithSPF.SPFRecords {
				if spfStatus.Check == 1 {
					hasInvalidSPF = true
					break
				}
			}
			relayWithSPF.CheckSPF = 1
			if !hasInvalidSPF {
				relayWithSPF.CheckSPF = 0
			}
		}

		res.Data.List = append(res.Data.List, relayWithSPF)
	}

	res.Data.Total = total
	res.SetSuccess("Success")
	return res, nil
}
func containsSPF(spf string, ip string, host string) bool {
	if ip != "" {
		ip4 := "ip4:" + ip
		return strings.Contains(spf, ip4)
	}
	if host != "" {
		include := "include:" + host
		return strings.Contains(spf, include)
	}
	return false
}

var (
	spfCache = gcache.New()
	mu       = &sync.Mutex{}
)

func GetRealSPFRecord(ctx context.Context, domain string) (string, error) {
	cacheKey := fmt.Sprintf("real_spf_record:%s", domain)

	if value, _ := spfCache.Get(ctx, cacheKey); value != nil {

		if value.String() == "not_found" {
			return "", fmt.Errorf("No SPF record found (from cache)")
		}
		return value.String(), nil
	}

	mu.Lock()
	defer mu.Unlock()

	if value, _ := spfCache.Get(ctx, cacheKey); value != nil {
		if value.String() == "not_found" {
			return "", fmt.Errorf("No SPF record found (from cache)")
		}
		return value.String(), nil
	}

	var spf string
	var finalErr error
	txts, err := net.LookupTXT(domain)
	if err != nil {
		g.Log().Debug(ctx, "DNS TXT query failed:", domain, "Error:", err)
		finalErr = err
	} else {
		found := false
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=spf1") {
				spf = txt
				found = true
				break
			}
		}
		if !found {
			finalErr = fmt.Errorf("No SPF record found")
		}
	}

	if spf != "" {

		spfCache.Set(ctx, cacheKey, spf, 5*time.Minute)
		return spf, nil
	} else {
		//  Unable to find or query failed. Cache the "not_found" flag with a validity period of 2 minute.
		spfCache.Set(ctx, cacheKey, "not_found", 2*time.Minute)
		return "", finalErr
	}
}
