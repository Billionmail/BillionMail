package database_initialization

import (
	"context"
	"github.com/gogf/gf/v2/frame/g"
)

func init() {

	registerHandler(func() {
		batchMailSQLList := []string{

			`CREATE TABLE IF NOT EXISTS bm_contact_groups (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    			token VARCHAR(30) NOT NULL DEFAULT '', 
    			double_optin SMALLINT NOT NULL DEFAULT 0, -- 0: Single Opt-in, 1: Double Opt-in
    			welcome_mail_html TEXT DEFAULT '', -- HTML content for welcome email
    			welcome_mail_drag TEXT DEFAULT '', -- Drag-and-drop content for welcome email
    			confirm_mail_html TEXT DEFAULT '', -- HTML content for confirmation email
    			confirm_mail_drag TEXT DEFAULT '', -- Drag-and-drop content for confirmation email
    			success_url TEXT DEFAULT '', -- URL to redirect after successful subscription
    			confirm_url TEXT DEFAULT '', -- URL to redirect after confirmation
    			already_url TEXT DEFAULT '', -- URL to redirect if already subscribed
    			subscribe_form TEXT DEFAULT '', -- HTML form for subscription
    			confirm_subject TEXT DEFAULT '', -- Confirmation Email Subject
    			welcome_subject TEXT DEFAULT '', -- Welcome Email Subject
    			send_welcome_email SMALLINT NOT NULL DEFAULT 0,--  0: No need to send email, 1: send email
    			unsubscribe_mail_html TEXT DEFAULT '', -- HTML content for unsubscribe email
				unsubscribe_mail_drag TEXT DEFAULT '', -- Drag-and-drop content for unsubscribe email
    			unsubscribe_subject TEXT DEFAULT 'You''re unsubscribed', -- Unsubscribe Email Subject
				unsubscribe_redirect_url TEXT DEFAULT '', -- URL to redirect after successful unsubscription
    			send_unsubscribe_email SMALLINT NOT NULL DEFAULT 0,
                UNIQUE(name)
            )`,

			`CREATE TABLE IF NOT EXISTS bm_contacts (
                id SERIAL PRIMARY KEY,
                email VARCHAR(320) NOT NULL,
                group_id INTEGER,
                active INTEGER DEFAULT 1,
                task_id INTEGER DEFAULT 0,
                create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                status INTEGER DEFAULT 0, -- 0: Unconfirmed, 1: Confirmed
                attribs   JSONB DEFAULT '{}'::jsonb,
				last_active_at INTEGER DEFAULT 0,
                FOREIGN KEY (group_id) REFERENCES bm_contact_groups(id) ON DELETE SET NULL,
                UNIQUE(group_id, email)
            )`,

			`CREATE TABLE IF NOT EXISTS email_templates (
                id SERIAL PRIMARY KEY,
                temp_name VARCHAR(255),
                chat_id VARCHAR(255),  -- ai chat id
                add_type SMALLINT NOT NULL DEFAULT 0,  -- // 0 html  1 drag  2 AI
                content TEXT NOT NULL DEFAULT '',
                render TEXT NOT NULL DEFAULT '',
                create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
    			UNIQUE(temp_name)
            )`,

			`CREATE TABLE IF NOT EXISTS email_tasks (
                id SERIAL PRIMARY KEY,
                task_name VARCHAR(255) NOT NULL,
                addresser VARCHAR(320) NOT NULL,
                subject TEXT,
                full_name VARCHAR(255),
                remark TEXT,
                recipient_count INTEGER NOT NULL,
                task_process SMALLINT NOT NULL DEFAULT 0,
                pause SMALLINT NOT NULL DEFAULT 0,
                template_id INTEGER NOT NULL,
                is_record SMALLINT NOT NULL DEFAULT 0,
                unsubscribe SMALLINT NOT NULL DEFAULT 0,
                threads INTEGER NOT NULL DEFAULT 0,
                etypes VARCHAR(320) NOT NULL DEFAULT '1',
                track_open SMALLINT NOT NULL DEFAULT 1,
                track_click SMALLINT NOT NULL DEFAULT 1,
                start_time INTEGER NOT NULL DEFAULT 0,
                create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                active SMALLINT NOT NULL DEFAULT 0,
    			add_type SMALLINT NOT NULL DEFAULT 0,
				sends_count INTEGER NOT NULL DEFAULT 0,
				delivered_count INTEGER NOT NULL DEFAULT 0,
				bounced_count INTEGER NOT NULL DEFAULT 0,
				deferred_count INTEGER NOT NULL DEFAULT 0,
				group_id INTEGER NOT NULL DEFAULT 0,   
				stats_update_time INTEGER NOT NULL DEFAULT 0,
				tag_ids TEXT DEFAULT '', -- JSON array of tag ids for filtering contacts
				tag_logic VARCHAR(10) DEFAULT 'AND' -- Tag logic (AND: must have all tags, OR: have any tag)
    
            )`,

			`CREATE TABLE IF NOT EXISTS recipient_info (
                id SERIAL PRIMARY KEY,
                task_id INTEGER NOT NULL,
                recipient VARCHAR(320) NOT NULL,
                is_sent SMALLINT DEFAULT 0, -- 0: Pending processing 2: Extracted and ready for transmission 1: Transmission completed
                sent_time INTEGER NOT NULL DEFAULT 0,
                message_id TEXT NOT NULL,
                create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                FOREIGN KEY (task_id) REFERENCES email_tasks(id) ON DELETE CASCADE,
                UNIQUE(task_id, recipient)
            )`,

			`CREATE TABLE IF NOT EXISTS unsubscribe_records (
                id SERIAL PRIMARY KEY,
                email VARCHAR(320) NOT NULL,
                group_id INTEGER,
                template_id INTEGER,
                task_id INTEGER,
                unsubscribe_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
            )`,

			`CREATE TABLE IF NOT EXISTS abnormal_recipient (
                id SERIAL PRIMARY KEY,
                create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                recipient VARCHAR(320) NOT NULL,
    			count INTEGER NOT NULL,
    			description VARCHAR(255) NOT NULL,   
    			add_type SMALLINT NOT NULL DEFAULT 0, 
    			UNIQUE(recipient)
            )`,

			`CREATE TABLE IF NOT EXISTS api_templates (
                id SERIAL PRIMARY KEY,
                api_key VARCHAR(64) NOT NULL,
                api_name VARCHAR(255) NOT NULL,
                template_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                addresser VARCHAR(320) NOT NULL,
                full_name VARCHAR(255),
                unsubscribe SMALLINT NOT NULL DEFAULT 0,
                track_open SMALLINT NOT NULL DEFAULT 1,
                track_click SMALLINT NOT NULL DEFAULT 1,
                active SMALLINT NOT NULL DEFAULT 1,
                create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                expire_time INTEGER DEFAULT 0,
                last_key_update_time INTEGER DEFAULT 0,
                UNIQUE(api_key)
            )`,

			`CREATE TABLE IF NOT EXISTS api_mail_logs (
                id SERIAL PRIMARY KEY,
                api_id INTEGER NOT NULL,
                recipient VARCHAR(320) NOT NULL,
                message_id TEXT NOT NULL,
                addresser VARCHAR(320) NOT NULL,
                status SMALLINT NOT NULL DEFAULT 0, -- 0:to send, 2:send, 3:send failed
                error_message TEXT, 
				attribs JSONB DEFAULT '{}'::jsonb,
                send_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
                create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())

            )`,

			`CREATE TABLE IF NOT EXISTS api_ip_whitelist (
				id SERIAL PRIMARY KEY,
				api_id INTEGER NOT NULL,
				ip VARCHAR(45) NOT NULL,
				create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				FOREIGN KEY (api_id) REFERENCES api_templates(id) ON DELETE CASCADE
			)`,

			`
			CREATE TABLE IF NOT EXISTS bm_tags (
				id SERIAL PRIMARY KEY,
				group_id INTEGER NOT NULL,  --  bm_contact_groups id
				name VARCHAR(100) NOT NULL,
				create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				UNIQUE(group_id, name) 
		)`,

			`
			CREATE TABLE IF NOT EXISTS bm_contact_tags (
				id SERIAL PRIMARY KEY,
				contact_id INTEGER NOT NULL,  --  bm_contacts id
				tag_id INTEGER NOT NULL,
				create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
				UNIQUE(contact_id, tag_id) 
		)`,

			`CREATE INDEX IF NOT EXISTS idx_unsubscribe_email ON unsubscribe_records (email)`,
			`CREATE INDEX IF NOT EXISTS idx_unsubscribe_time ON unsubscribe_records (unsubscribe_time)`,
			`CREATE INDEX IF NOT EXISTS idx_bm_contacts_email ON bm_contacts (email)`,
			`CREATE INDEX IF NOT EXISTS idx_bm_contacts_active ON bm_contacts (active)`,
			`CREATE INDEX IF NOT EXISTS idx_abnormal_recipient_count ON abnormal_recipient (recipient,count)`,
			`CREATE INDEX IF NOT EXISTS idx_group_email ON bm_contacts(group_id, email)`,
			`CREATE INDEX IF NOT EXISTS idx_api_mail_logs_api_id ON api_mail_logs (api_id)`,
			`CREATE INDEX IF NOT EXISTS idx_api_mail_logs_recipient ON api_mail_logs (recipient)`,
			`CREATE INDEX IF NOT EXISTS idx_api_mail_logs_message_id ON api_mail_logs (message_id)`,
			`CREATE INDEX IF NOT EXISTS idx_recipient_info_task_id ON recipient_info(task_id)`,
			`CREATE INDEX IF NOT EXISTS idx_recipient_info_is_sent ON recipient_info(is_sent)`,
			`CREATE INDEX IF NOT EXISTS idx_recipient_info_message_id ON recipient_info(message_id)`,
			`CREATE INDEX IF NOT EXISTS idx_recipient_info_task_sent ON recipient_info(task_id, is_sent)`,
			`CREATE INDEX IF NOT EXISTS idx_email_tasks_task_process ON email_tasks(task_process)`,
			`CREATE INDEX IF NOT EXISTS idx_bm_tags_group_id ON bm_tags(group_id)`,
			`CREATE INDEX IF NOT EXISTS idx_bm_contact_tags_contact_id ON bm_contact_tags(contact_id)`,
			`CREATE INDEX IF NOT EXISTS idx_bm_contact_tags_tag_id ON bm_contact_tags(tag_id)`,
		}

		for _, sql := range batchMailSQLList {
			_, err := g.DB().Exec(context.Background(), sql)
			if err != nil {
				g.Log().Error(context.Background(), "Failed to execute batch mail SQL:", err, sql)
				return
			}
		}
		// bm_contacts
		_ = AddColumnIfNotExists("bm_contacts", "attribs", "JSONB", "'{}'::jsonb", false)
		_ = AddColumnIfNotExists("bm_contacts", "status", "INTEGER", "1", true)
		_ = AddColumnIfNotExists("bm_contacts", "last_active_at", "INTEGER", "0", true)

		//  api_mail_logs
		_ = AddColumnIfNotExists("api_mail_logs", "status", "SMALLINT", "0", true)
		_ = AddColumnIfNotExists("api_mail_logs", "error_message", "TEXT", "''", false)
		_ = AddColumnIfNotExists("api_mail_logs", "create_time", "INTEGER", "EXTRACT(EPOCH FROM NOW())", true)
		_ = AddColumnIfNotExists("api_mail_logs", "attribs", "JSONB", "'{}'::jsonb", false)

		//bm_contact_groups
		_ = AddColumnIfNotExists("bm_contact_groups", "token", "VARCHAR(30)", "''", true)
		_ = AddColumnIfNotExists("bm_contact_groups", "double_optin", "SMALLINT", "0", true)
		_ = AddColumnIfNotExists("bm_contact_groups", "success_url", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "confirm_url", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "already_url", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "subscribe_form", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "welcome_mail_html", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "welcome_mail_drag", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "confirm_mail_html", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "confirm_mail_drag", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "confirm_subject", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "welcome_subject", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "send_welcome_email", "SMALLINT", "0", true)

		_ = AddColumnIfNotExists("bm_contact_groups", "unsubscribe_mail_html", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "unsubscribe_mail_drag", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "unsubscribe_subject", "TEXT", "'You''re unsubscribed'", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "unsubscribe_redirect_url", "TEXT", "''", false)
		_ = AddColumnIfNotExists("bm_contact_groups", "send_unsubscribe_email", "SMALLINT", "0", true)

		//email_templates
		_ = AddColumnIfNotExists("email_templates", "chat_id", "VARCHAR(255)", "''", false)

		// email_tasks
		_ = AddColumnIfNotExists("email_tasks", "sends_count", "INTEGER", "0", true)
		_ = AddColumnIfNotExists("email_tasks", "delivered_count", "INTEGER", "0", true)
		_ = AddColumnIfNotExists("email_tasks", "bounced_count", "INTEGER", "0", true)
		_ = AddColumnIfNotExists("email_tasks", "deferred_count", "INTEGER", "0", true)
		_ = AddColumnIfNotExists("email_tasks", "stats_update_time", "INTEGER", "0", true)
		_ = AddColumnIfNotExists("email_tasks", "group_id", "INTEGER", "0", true)
		_ = AddColumnIfNotExists("email_tasks", "tag_ids", "TEXT", "''", false)
		_ = AddColumnIfNotExists("email_tasks", "tag_logic", "VARCHAR(10)", "'AND'", false)

		// unsubscribe_records
		_ = DropForeignKeyIfExists("unsubscribe_records", "group_id")
		_ = DropForeignKeyIfExists("unsubscribe_records", "template_id")
		_ = DropForeignKeyIfExists("unsubscribe_records", "task_id")

		_ = DropForeignKeyIfExists("email_tasks", "template_id")

		g.Log().Info(context.Background(), "Batch mail tables initialized successfully")
	})
}
