package mail_boxes

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/dockerapi"
	"billionmail-core/internal/service/public"
	"bufio"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var domainUsageColumnEnsured int32 // 0-Unverified, 1-Verified

// -----------------------------
// Scheduled check for update of domain email quota usage - used_quota
// -----------------------------

type mailboxUsage struct {
	user string
	used int64
}

func UpdateMailboxesUsedSpace() {
	ctx := context.Background()

	type row struct {
		Username  string
		LocalPart string
		Domain    string
		UsedQuota int64
	}
	var list []row
	if err := g.DB().Model("mailbox").
		Fields("username,local_part,domain,COALESCE(used_quota,0) used_quota").
		Where("active=1 AND COALESCE(quota_active,1)=1").
		Scan(&list); err != nil {
		g.Log().Error(ctx, "query mailbox list failed", err)
		return
	}
	if len(list) == 0 {

		return
	}

	root := public.AbsPath("../vmail-data")

	dk, _ := docker.NewDockerAPI()
	defer func() {
		if dk != nil {
			dk.Close()
		}
	}()

	workerCount := 8
	if c := g.Cfg().MustGet(ctx, "quota.worker").Int(); c > 0 && c <= 64 {
		workerCount = c
	}

	jobs := make(chan row, len(list))
	var wg sync.WaitGroup
	results := make(chan mailboxUsage, len(list))

	//  maildirsize
	workerFn := func() {
		defer wg.Done()
		for mb := range jobs {
			userDir := filepath.Join(root, mb.Domain, mb.LocalPart)

			size, err := readMaildirsize(userDir)

			if err != nil {
				if dk != nil && (err == nil || err.Error() == "file not exists") {
					if _, e2 := dk.ExecCommandByName(ctx, consts.SERVICES.Dovecot, []string{"doveadm", "quota", "recalc", "-u", mb.Username}, "root"); e2 == nil {
						size, err = readMaildirsize(userDir)
					}
				}
			}
			if err != nil {
				continue
			}
			results <- mailboxUsage{user: mb.Username, used: size}
		}
	}

	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go workerFn()
	}

	for _, mb := range list {
		jobs <- mb
	}
	close(jobs)
	wg.Wait()
	close(results)

	var updates []mailboxUsage
	for r := range results {

		var oldUsed int64
		for _, mb := range list {
			if mb.Username == r.user {
				oldUsed = mb.UsedQuota
				break
			}
		}
		if r.used != oldUsed {
			updates = append(updates, r)
		}
	}

	if len(updates) == 0 {

		return
	}

	updateInTransaction(ctx, updates)

	aggregateDomainUsage(ctx)

	//g.Log().Debug(ctx, "update completed", "scanned", len(list), "changed", len(updates), "elapsed", time.Since(start))
}

func updateInTransaction(ctx context.Context, updates []mailboxUsage) {
	const batchSize = 300
	successCount := 0
	failCount := 0

	for i := 0; i < len(updates); i += batchSize {
		end := i + batchSize
		if end > len(updates) {
			end = len(updates)
		}
		batch := updates[i:end]

		tx, err := g.DB().Begin(ctx)
		if err != nil {

			failCount += len(batch)
			continue
		}

		batchSuccess := 0
		batchFailed := 0

		for _, u := range batch {
			result, err := tx.Exec(
				`UPDATE mailbox 
                 SET used_quota = ? 
                 WHERE username = ?`,
				u.used, u.user,
			)
			if err != nil {
				g.Log().Warning(ctx, "Single update failed", "user", u.user, "used", u.used, "err", err)
				batchFailed++
			} else {
				affected, _ := result.RowsAffected()
				if affected == 0 {
					g.Log().Debug(ctx, "User not found: ", u.user)
				}
				batchSuccess++
			}
		}

		if batchFailed > 0 {
			tx.Rollback()
			failCount += batchFailed
			successCount += batchSuccess
		} else {
			if err := tx.Commit(); err != nil {

				failCount += len(batch)
			} else {
				successCount += batchSuccess
			}
		}
	}

	//g.Log().Debug(ctx, "Batch update completed", "success", successCount, "failed", failCount)
}

func readMaildirsize(userDir string) (int64, error) {
	path := filepath.Join(userDir, "maildirsize")

	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open maildirsize failed: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var total int64
	var lineNo int

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		if lineNo == 1 {

			continue
		}

		sizeStr := parts[0]

		sizeStr = strings.TrimSuffix(sizeStr, "S")

		v, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse maildirsize line %d: invalid size '%s': %w", lineNo, sizeStr, err)
		}
		total += v
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan maildirsize failed: %w", err)
	}

	return total, nil
}

// domain.current_usage
func aggregateDomainUsage(ctx context.Context) {

	if atomic.LoadInt32(&domainUsageColumnEnsured) == 0 {
		if _, err := g.DB().Exec(ctx, "ALTER TABLE domain ADD COLUMN IF NOT EXISTS current_usage BIGINT NOT NULL DEFAULT 0"); err != nil {
			g.Log().Warning(ctx, "ensure domain.current_usage column failed", err)
		}
		atomic.StoreInt32(&domainUsageColumnEnsured, 1)
	}

	type dRow struct {
		Domain string
		Usage  int64
	}
	var rows []dRow
	if err := g.DB().Model("mailbox").Fields("domain as domain, SUM(used_quota) as usage").Where("active=1").Group("domain").Scan(&rows); err != nil {
		g.Log().Warning(ctx, "aggregate domain usage query failed", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	for _, r := range rows {
		if _, err := g.DB().Model("domain").Where("domain", r.Domain).Update(g.Map{"current_usage": r.Usage}); err != nil {
			g.Log().Warning(ctx, "update domain current_usage failed", r.Domain, err)
		}
	}
}
