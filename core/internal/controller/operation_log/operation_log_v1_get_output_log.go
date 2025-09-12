package operation_log

import (
	"billionmail-core/internal/service/public"
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"billionmail-core/api/operation_log/v1"
)

func (c *ControllerV1) GetOutputLog(ctx context.Context, req *v1.GetOutputLogReq) (res *v1.GetOutputLogRes, err error) {
	res = &v1.GetOutputLogRes{}

	files, err := getLogFilesInRange(ctx, req.StartDate, req.EndDate)
	if err != nil {
		res.SetError(errors.New(public.LangCtx(ctx, "No log files found in the given date range")))
		return res, nil
	}

	keyword := strings.TrimSpace(req.Keyword)
	page := req.Page
	pageSize := req.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {

		pageSize = 1000
	}

	var collectedLines []string
	var linesToSkip int
	if pageSize > 0 {
		linesToSkip = (page - 1) * pageSize
	}

	for i := len(files) - 1; i >= 0; i-- {
		file := files[i]

		lines, readErr := readLines(file, keyword)
		if readErr != nil {
			continue
		}

		if pageSize <= 0 {

			collectedLines = append(lines, collectedLines...)
			continue
		}

		for j := len(lines) - 1; j >= 0; j-- {

			if linesToSkip > 0 {
				linesToSkip--
				continue
			}

			collectedLines = append(collectedLines, lines[j])

			if len(collectedLines) >= pageSize {
				goto endLoop
			}
		}
	}

endLoop:

	reverseLines(collectedLines)

	merged := strings.Join(collectedLines, "\n")

	res.SetSuccess(public.LangCtx(ctx, "Success"))
	res.Data = merged
	return res, nil
}

func readLines(path, keyword string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if keyword == "" || strings.Contains(line, keyword) {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func reverseLines(lines []string) {
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
}

func getLogFilesInRange(ctx context.Context, start, end string) ([]string, error) {
	logDir := public.AbsPath("../logs/core/out")
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
		return nil, fmt.Errorf("no log files found")
	}
	return files, nil
}
