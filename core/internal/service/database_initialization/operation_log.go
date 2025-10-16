package database_initialization

import (
	"context"
	"github.com/gogf/gf/v2/frame/g"
)

func init() {
	registerHandler(func() {
		sqlList := []string{

			`-- operation_log
			CREATE TABLE IF NOT EXISTS bm_operation_logs (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL DEFAULT 0,
			type VARCHAR(64) NOT NULL,
			log TEXT NOT NULL,
			ip VARCHAR(64) NOT NULL,
			info TEXT NOT NULL,
			addtime INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
		)`,
			`CREATE INDEX IF NOT EXISTS idx_log_user_time ON bm_operation_logs(user_id, addtime);`,
			`CREATE INDEX IF NOT EXISTS idx_log_type ON bm_operation_logs(type);`,
			`CREATE INDEX IF NOT EXISTS idx_log_addtime ON bm_operation_logs(addtime);`,
			`CREATE INDEX IF NOT EXISTS idx_log_ip ON bm_operation_logs(ip);`,
			`CREATE INDEX IF NOT EXISTS idx_log_log ON bm_operation_logs(log);`,
			`CREATE INDEX IF NOT EXISTS idx_log_info ON bm_operation_logs(info);`,
		}

		for _, sql := range sqlList {
			_, err := g.DB().Exec(context.Background(), sql)
			if err != nil {
				g.Log().Error(context.Background(), "Failed to create billion-mail options table:", err)
				return
			}
		}
	})
}
