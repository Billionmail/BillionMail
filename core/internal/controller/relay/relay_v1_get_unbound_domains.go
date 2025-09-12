package relay

import (
	"billionmail-core/api/relay/v1"
	"billionmail-core/internal/service/public"
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
)

type DomainEntity struct {
	Domain string `json:"domain"`
}

func (c *ControllerV1) GetUnboundDomains(ctx context.Context, req *v1.GetUnboundDomainsReq) (res *v1.GetUnboundDomainsRes, err error) {
	res = &v1.GetUnboundDomainsRes{}

	var domainEntities []DomainEntity
	err = g.DB().Model("domain").
		Fields("domain").
		Where("active", 1). // 只查询激活的域名
		Scan(&domainEntities)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get domain list: {}", err.Error())))
		return res, nil
	}

	var boundDomainEntities []struct {
		SenderDomain string `json:"sender_domain"`
	}
	err = g.DB().Model("bm_relay_domain_mapping").
		Fields("sender_domain").
		Scan(&boundDomainEntities)
	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to get the domain name of the bound relay: {}", err.Error())))
		return res, nil
	}

	boundDomainsMap := make(map[string]bool)
	for _, entity := range boundDomainEntities {

		domain := entity.SenderDomain
		if len(domain) > 0 && domain[0] == '@' {
			domain = domain[1:]
		}
		boundDomainsMap[domain] = true
	}

	domainInfoList := make([]*v1.DomainInfo, 0, len(domainEntities))
	for _, entity := range domainEntities {
		domain := entity.Domain
		isBound := boundDomainsMap[domain]

		domainInfo := &v1.DomainInfo{
			Domain:  domain,
			IsBound: isBound,
		}
		domainInfoList = append(domainInfoList, domainInfo)
	}

	res.Data = domainInfoList
	res.SetSuccess(public.LangCtx(ctx, "Get the domain list successfully"))

	return res, nil
}
