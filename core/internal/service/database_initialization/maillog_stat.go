package database_initialization

import (
	"context"
	"github.com/gogf/gf/v2/frame/g"
)

func init() {
	registerHandler(func() {
		sqlList := []string{
			`-- Mail removal records from queue
			CREATE TABLE IF NOT EXISTS mailstat_removed (
				postfix_message_id TEXT PRIMARY KEY,
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS removed_logTime ON mailstat_removed (log_time)`,
			`CREATE INDEX IF NOT EXISTS removed_logTime_millis ON mailstat_removed (log_time_millis)`,

			`-- Mail MessageIDs
			CREATE TABLE IF NOT EXISTS mailstat_message_ids (
				postfix_message_id TEXT PRIMARY KEY,
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
				message_id TEXT NOT NULL DEFAULT ''
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS messageIds_logTime ON mailstat_message_ids (log_time)`,
			`CREATE INDEX IF NOT EXISTS messageIds_logTime_millis ON mailstat_message_ids (log_time_millis)`,
			`CREATE INDEX IF NOT EXISTS messageIds_messageId ON mailstat_message_ids (message_id)`,

			`-- Mail senders
			CREATE TABLE IF NOT EXISTS mailstat_senders (
				postfix_message_id TEXT PRIMARY KEY,
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
				size INTEGER NOT NULL DEFAULT 0,
				sender TEXT NOT NULL DEFAULT ''
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS senders_logTime_size_sender ON mailstat_senders (log_time, size, sender)`,
			`CREATE INDEX IF NOT EXISTS senders_logTime_millis ON mailstat_senders (log_time_millis)`,

			`-- Mail sending records (unique records, keep latest)
			CREATE TABLE IF NOT EXISTS mailstat_send_mails (
				postfix_message_id TEXT PRIMARY KEY,
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
				status TEXT NOT NULL DEFAULT '',
				recipient TEXT NOT NULL DEFAULT '',
				mail_provider TEXT NOT NULL DEFAULT '',
				delay REAL NOT NULL DEFAULT 0,
				delays TEXT NOT NULL DEFAULT '',
				dsn TEXT NOT NULL DEFAULT '',
				relay TEXT NOT NULL DEFAULT '',
				description TEXT NOT NULL DEFAULT ''
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS sendMails_logTime_status_recipient ON mailstat_send_mails (log_time, status, recipient)`,
			`CREATE INDEX IF NOT EXISTS sendMails_logTime_millis ON mailstat_send_mails (log_time_millis)`,
			`CREATE INDEX IF NOT EXISTS sendMails_logTime_status_mailProvider ON mailstat_send_mails (log_time, status, mail_provider)`,

			`-- Mail receiving records (unique records, keep latest)
			CREATE TABLE IF NOT EXISTS mailstat_receive_mails (
				postfix_message_id TEXT PRIMARY KEY,
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
				status TEXT NOT NULL DEFAULT '',
				recipient TEXT NOT NULL DEFAULT '',
				delay REAL NOT NULL DEFAULT 0,
				delays TEXT NOT NULL DEFAULT '',
				dsn TEXT NOT NULL DEFAULT '',
				relay TEXT NOT NULL DEFAULT '',
				description TEXT NOT NULL DEFAULT ''
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS receiveMails_logTime_status_recipient ON mailstat_receive_mails (log_time, status, recipient)`,
			`CREATE INDEX IF NOT EXISTS receiveMails_logTime_millis ON mailstat_receive_mails (log_time_millis)`,

			`-- Mail deferred records
			CREATE TABLE IF NOT EXISTS mailstat_deferred_mails (
				id SERIAL PRIMARY KEY,
				postfix_message_id TEXT NOT NULL DEFAULT '',
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
				delay REAL NOT NULL DEFAULT 0,
				delays TEXT NOT NULL DEFAULT '',
				dsn TEXT NOT NULL DEFAULT '',
				relay TEXT NOT NULL DEFAULT '',
				description TEXT NOT NULL DEFAULT ''
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS deferredMails_postfixMessageId_logTime ON mailstat_deferred_mails (postfix_message_id, log_time)`,
			`CREATE INDEX IF NOT EXISTS deferredMails_logTime_millis ON mailstat_deferred_mails (log_time_millis)`,

			`-- Mail open tracking records
			CREATE TABLE IF NOT EXISTS mailstat_opened (
				id SERIAL PRIMARY KEY,
				campaign_id INTEGER NOT NULL DEFAULT 0,
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
				recipient TEXT NOT NULL DEFAULT '',
				postfix_message_id TEXT NOT NULL DEFAULT '',
				message_id TEXT NOT NULL DEFAULT ''
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS opened_postfixMessageId_logTime ON mailstat_opened (postfix_message_id, log_time)`,
			`CREATE INDEX IF NOT EXISTS opened_logTime_millis ON mailstat_opened (log_time_millis)`,
			`CREATE INDEX IF NOT EXISTS opened_campaignId_logTime ON mailstat_opened (campaign_id, log_time)`,

			`-- Mail click tracking records
			CREATE TABLE IF NOT EXISTS mailstat_clicked (
				id SERIAL PRIMARY KEY,
				campaign_id INTEGER NOT NULL DEFAULT 0,
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
				recipient TEXT NOT NULL DEFAULT '',
				url TEXT NOT NULL DEFAULT '',
				postfix_message_id TEXT NOT NULL DEFAULT '',
				message_id TEXT NOT NULL DEFAULT ''
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS clicked_postfixMessageId_logTime_url ON mailstat_clicked (postfix_message_id, log_time, url)`,
			`CREATE INDEX IF NOT EXISTS clicked_logTime_millis ON mailstat_clicked (log_time_millis)`,
			`CREATE INDEX IF NOT EXISTS clicked_campaignId_logTime_url_recipient ON mailstat_clicked (campaign_id, log_time, url, recipient)`,

			`-- Mail complaint/FBL records
			CREATE TABLE IF NOT EXISTS mailstat_complaints (
				id SERIAL PRIMARY KEY,
				postfix_message_id TEXT NOT NULL DEFAULT '',
				recipient TEXT NOT NULL DEFAULT '',
				log_time_millis BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::INTEGER),
				log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED
			)`,

			`-- Indexes
			CREATE INDEX IF NOT EXISTS complaints_postfixMessageId_logTime ON mailstat_complaints (postfix_message_id, log_time)`,
			`CREATE INDEX IF NOT EXISTS complaints_logTime_millis ON mailstat_complaints (log_time_millis)`,
		}

		for _, sql := range sqlList {
			_, err := g.DB().Exec(context.Background(), sql)
			if err != nil {
				g.Log().Error(context.Background(), "Failed to create mail log statistics tables:", err)
				return
			}
		}
	})
}
