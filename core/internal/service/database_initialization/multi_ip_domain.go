package database_initialization

import (
	"context"
	"github.com/gogf/gf/v2/frame/g"
)

func init() {
	registerHandler(func() {
		sqlList := []string{

			`-- Multi-IP Domain Configuration
			CREATE TABLE IF NOT EXISTS bm_multi_ip_domain (
			id SERIAL PRIMARY KEY,
			domain VARCHAR(255) NOT NULL,
			outbound_ip VARCHAR(45) NOT NULL, 
			network_name VARCHAR(100) NOT NULL,  -- Docker network name
			subnet VARCHAR(20) NOT NULL,
			postfix_ip VARCHAR(45) NOT NULL, -- Postfix container IP
			aliases VARCHAR(255) NOT NULL, -- Docker service alias
			smtp_server_name VARCHAR(100) NOT NULL, -- SMTP service name
			active smallint NOT NULL DEFAULT 1, 
			create_time int NOT NULL default 0,
			update_time int NOT NULL default 0,
			status VARCHAR(20) NOT NULL DEFAULT 'pending', -- current state: applied, failed, pending, applying
			UNIQUE(domain, outbound_ip)

		) `,

			`CREATE INDEX IF NOT EXISTS idx_bm_multi_ip_domain_active ON bm_multi_ip_domain(active)`,
			`CREATE INDEX IF NOT EXISTS idx_bm_multi_ip_domain_domain ON bm_multi_ip_domain(domain)`,
			`CREATE INDEX IF NOT EXISTS idx_bm_multi_ip_domain_outbound_ip ON bm_multi_ip_domain(outbound_ip)`,
		}

		for _, sql := range sqlList {
			_, err := g.DB().Exec(context.Background(), sql)
			if err != nil {
				g.Log().Error(context.Background(), "Failed to create mail server tables:", err)
				return
			}
		}

		// domain
		//_ = AddColumnIfNotExists("domain", "urls", "TEXT[]", "'{}'::TEXT[]", false)

	})
}
