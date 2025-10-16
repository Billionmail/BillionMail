package mail_boxes

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"context"
	"errors"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Initialize quota plugin. If not installed, install it first.
// Modify dovecot.conf, 20-pop3.conf, and 90-quota.conf.
// Rebuild dovecot-sql.conf.ext
// Check all mailboxes and add the maildirsize file (make sure the file permissions are correct)

func InitQuotaPluginAndUpdateUsedSpace(ctx context.Context) error {
	if public.HostWorkDir == "" {
		return errors.New("HostWorkDir not set")
	}

	markPath := public.AbsPath("../core/data/quota_init_done.mark")

	if gfile.Exists(markPath) {
		return nil
	}

	confRoot := public.AbsPath("../conf/dovecot")

	if _, err := os.Stat(confRoot); os.IsNotExist(err) {
		return fmt.Errorf("dovecot conf dir not found: %s", confRoot)
	}

	// 1. Modify dovecot.conf
	if err := ensureDovecotConf(confRoot); err != nil {
		return err
	}

	// 2. Modify 20-pop3.conf
	if err := ensurePop3Conf(confRoot); err != nil {
		g.Log().Debug(ctx, " Modify 20-pop3.conf err:", err)
		return err
	}

	// 3. /conf.d/90-quota.conf
	if err := ensureQuotaConf(confRoot); err != nil {
		g.Log().Debug(ctx, " Modify /conf.d/90-quota.conf err:", err)
		return err
	}

	// 4. Rebuild dovecot-sql.conf.ext
	if err := recreateSqlConf(confRoot); err != nil {
		g.Log().Debug(ctx, " Rebuild dovecot-sql.conf.ext err:", err)
		return err
	}

	// 5.  maildirsize
	if err := AddMaildirsizeFileForAllMailboxes(ctx); err != nil {
		return err
	}

	// 6. mark & reload dovecot (best-effort)
	if err := gfile.PutContents(markPath, fmt.Sprintf("First sync completed at %s", time.Now().Format("2006-01-02 15:04:05"))); err != nil {
		g.Log().Warningf(ctx, "Failed to create the quota marker file: %v", err)
	}

	if err := reloadDovecot(ctx); err != nil {
		g.Log().Warning(ctx, "reload dovecot failed", err)
	}

	g.Log().Info(ctx, "Quota plugin initialization completed")
	return nil
}

func ensureDovecotConf(confRoot string) error {
	path := filepath.Join(confRoot, "dovecot.conf")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read dovecot.conf failed: %w", err)
	}
	content := string(data)

	// Search for the "mail_plugins" line
	mailPluginsRe := regexp.MustCompile(`(?m)^\s*mail_plugins\s*=.*$`)
	if mailPluginsRe.MatchString(content) {
		// If it exists but there is no quota, add a quota.
		newContent := mailPluginsRe.ReplaceAllStringFunc(content, func(line string) string {
			if strings.Contains(line, "quota") {
				return line
			}
			return line + " quota"
		})
		content = newContent
	} else {
		// Insert before the first !include
		includeIdx := strings.Index(content, "!include")
		if includeIdx > -1 {
			content = content[:includeIdx] + "mail_plugins = quota\n" + content[includeIdx:]
		} else {
			content = "mail_plugins = quota\n" + content
		}
	}
	return ioutil.WriteFile(path, []byte(content), 0644)
}

func ensurePop3Conf(confRoot string) error {
	path := filepath.Join(confRoot, "conf.d", "20-pop3.conf")

	data, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		tpl := "protocol pop3 {\n  mail_plugins = $mail_plugins\n}\n"
		return ioutil.WriteFile(path, []byte(tpl), 0644)
	}
	if err != nil {
		return err
	}

	content := string(data)

	if !strings.Contains(content, "\n  mail_plugins = $mail_plugins") &&
		!strings.Contains(content, "\n\tmail_plugins = $mail_plugins") &&
		!strings.Contains(content, "^mail_plugins = \\$mail_plugins$") {

		content = strings.ReplaceAll(content, "#mail_plugins = $mail_plugins", "  mail_plugins = $mail_plugins")

		if !strings.Contains(content, "mail_plugins = $mail_plugins") {
			content = strings.Replace(content, "protocol pop3 {", "protocol pop3 {\n  mail_plugins = $mail_plugins", 1)
		}
	}

	return ioutil.WriteFile(path, []byte(content), 0644)
}

func ensureQuotaConf(confRoot string) error {
	path := filepath.Join(confRoot, "conf.d", "90-quota.conf")

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ioutil.WriteFile(path, []byte("plugin {\n  quota = maildir\n}\n"), 0644)
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	if strings.Contains(content, "quota = maildir") &&
		!strings.Contains(content, "#quota = maildir") &&
		!strings.Contains(content, "/*quota = maildir") {
		return nil // 已正确启用
	}

	if strings.Contains(content, "plugin {") && !strings.Contains(content, "quota = maildir") {
		content = strings.Replace(content, "plugin {", "plugin {\n  quota = maildir", 1)
	} else {

		content += "\nplugin {\n  quota = maildir\n}\n"
	}

	return ioutil.WriteFile(path, []byte(content), 0644)
}

func recreateSqlConf(confRoot string) error {
	path := filepath.Join(confRoot, "conf.d", "dovecot-sql.conf.ext")

	//data, err := ioutil.ReadFile(path)
	//if err != nil {
	//	return fmt.Errorf("read back dovecot-sql.conf.ext failed: %w", err)
	//}

	dbPass, _ := public.DockerEnv("DBPASS")
	dbName, _ := public.DockerEnv("DBNAME")
	dbUser, _ := public.DockerEnv("DBUSER")

	content := fmt.Sprintf(`driver = pgsql
connect = host=pgsql dbname=%s user=%s password=%s

default_pass_scheme = MD5-CRYPT

user_query = SELECT '/var/vmail/%%d/%%n' as home, 'maildir:/var/vmail/%%d/%%n' as mail, 150 AS uid, 8 AS gid, 'maildir:storage=' || quota AS quota FROM mailbox WHERE username = '%%u' AND active = 1

password_query = SELECT username as user, password, '/var/vmail/%%d/%%n' as userdb_home, 'maildir:/var/vmail/%%d/%%n' as userdb_mail, 150 as userdb_uid, 8 as userdb_gid FROM mailbox WHERE username = '%%u' AND active = 1
`, dbName, dbUser, dbPass)

	err := ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("333333write new dovecot-sql.conf.ext failed: %w", err)
	}

	return nil
}

func AddMaildirsizeFileForAllMailboxes(ctx context.Context) error {

	if _, err := g.DB().Exec(ctx, "ALTER TABLE mailbox ADD COLUMN IF NOT EXISTS quota_active SMALLINT NOT NULL DEFAULT 1"); err != nil {
		g.Log().Warning(ctx, "ensure quota_active column failed", err)
	}

	type Row struct {
		Username    string
		LocalPart   string
		Domain      string
		Quota       int64
		QuotaActive int
	}
	var rows []Row
	if err := g.DB().Model("mailbox").Fields("username, local_part, domain, quota, COALESCE(quota_active,1) as quota_active").Scan(&rows); err != nil {

		return err
	}
	if len(rows) == 0 {

		return nil
	}

	vmailRoot := public.AbsPath("../vmail-data")

	for _, r := range rows {
		userDir := filepath.Join(vmailRoot, r.Domain, r.LocalPart)
		maildirsizePath := filepath.Join(userDir, "maildirsize")

		//if !public.IsDir(userDir) {
		//	continue
		//}

		if err := os.MkdirAll(userDir, 0755); err != nil {
			g.Log().Warning(ctx, "create userDir failed", r.Username, err)
			continue
		}

		// userDir (uid=150, gid=8)
		if err := public.ChownDovecot(userDir); err != nil {
			g.Log().Warning(ctx, "chown userDir failed", r.Username, err)

		}

		// maildirsize
		if gfile.Exists(maildirsizePath) {

			if err := public.ChownDovecot(userDir); err != nil {
				g.Log().Warning(ctx, "chown maildirsize failed", r.Username, err)
			}
			//g.Log().Debug(ctx, "maildirsize already exists, skipped", r.Username, maildirsizePath)
			continue
		} else {
			// not exist, create
			firstLineQuota := int64(0)
			if r.QuotaActive == 1 && r.Quota > 0 {
				firstLineQuota = r.Quota
			}
			content := fmt.Sprintf("%dS\n0 0\n", firstLineQuota)

			// 使用 gfile.PutContents（自动创建目录，原子写入）
			if err := gfile.PutContents(maildirsizePath, content); err != nil {
				g.Log().Warning(ctx, "write maildirsize failed", r.Username, err)
				continue
			}

			if err := public.ChownDovecot(userDir); err != nil {
				g.Log().Warning(ctx, "chown maildirsize failed after write", r.Username, err)
			}
			g.Log().Debug(ctx, "created maildirsize", r.Username, maildirsizePath)
		}

	}

	dk, err := docker.NewDockerAPI()
	if err != nil {
		g.Log().Warning(ctx, "docker api init failed", err)
		return err
	}
	defer dk.Close()
	for _, r := range rows {
		if r.QuotaActive == 1 && r.Quota > 0 {

			cmd := []string{"doveadm", "quota", "recalc", "-u", r.Username}
			_, err = dk.ExecCommandByName(context.Background(), consts.SERVICES.Dovecot, cmd, "root")

			if err != nil {
				g.Log().Warning(ctx, "doveadm recalc failed", r.Username, err)
			}

		}
	}

	return nil
}

func reloadDovecot(ctx context.Context) error {
	dk, err := docker.NewDockerAPI()
	if err != nil {
		return err
	}
	defer dk.Close()
	// Try systemctl reload, fallback to sending SIGHUP via doveadm
	if _, err := dk.ExecCommandByName(ctx, consts.SERVICES.Dovecot, []string{"dovecot", "reload"}, "root"); err != nil {
		return err
	}
	return nil
}
