package operation_log

import (
	"billionmail-core/internal/service/public"
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"billionmail-core/api/operation_log/v1"
)

func (c *ControllerV1) GetOutputLog(ctx context.Context, req *v1.GetOutputLogReq) (res *v1.GetOutputLogRes, err error) {
	files, err := getLogFilesInRange(ctx, req.StartDate, req.EndDate)
	if err != nil {
		return nil, err
	}
	keyword := strings.TrimSpace(req.Keyword)

	var allLines []string

	// // Reverse order
	// for i := len(files) - 1; i >= 0; i-- {
	// 	file := files[i]
	// 	f, err := os.Open(file)
	// 	if err != nil {
	// 		continue
	// 	}
	// 	var lines []string
	// 	scanner := bufio.NewScanner(f)
	// 	for scanner.Scan() {
	// 		line := scanner.Text()
	// 		if keyword == "" || strings.Contains(line, keyword) {
	// 			lines = append(lines, line)
	// 		}
	// 	}
	// 	f.Close()
	// 	for j := len(lines) - 1; j >= 0; j-- {
	// 		allLines = append(allLines, lines[j])
	// 	}
	// }

	// Normal order
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if keyword == "" || strings.Contains(line, keyword) {
				allLines = append(allLines, line)
			}
		}
		f.Close()
	}

	merged := strings.Join(allLines, "\n")

	res = &v1.GetOutputLogRes{}
	res.SetSuccess(public.LangCtx(ctx, "Success"))
	res.Data = merged

	return
}

func getLogFilesInRange(ctx context.Context, start, end string) ([]string, error) {
	var logDir = public.HostWorkDir + "/logs/core/out"
	layout := "2006-01-02"
	startDate, err := time.Parse(layout, start)
	if err != nil {
		return nil, fmt.Errorf("invalid start_date: %v", err)
	}
	endDate, err := time.Parse(layout, end)
	if err != nil {
		return nil, fmt.Errorf("invalid end_date: %v", err)
	}
	if endDate.Before(startDate) {
		return nil, fmt.Errorf("end_date must not be before start_date")
	}

	var files []string
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		fname := filepath.Join(logDir, d.Format("2006-01-02")+".log")
		if _, err := os.Stat(fname); err == nil {
			files = append(files, fname)
		}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no log files found in the given date range")
	}
	return files, nil
}
