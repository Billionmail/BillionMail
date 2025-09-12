package operation_log

import (
	"billionmail-core/api/operation_log/v1"
	"billionmail-core/internal/service/public"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const latestLogLinesLimit = 1000

func (c *ControllerV1) GetLatestOutputLog(ctx context.Context, req *v1.GetLatestOutputLogReq) (res *v1.GetLatestOutputLogRes, err error) {
	res = &v1.GetLatestOutputLogRes{}

	files, err := getSortedLogFiles()
	if err != nil {
		res.SetError(errors.New(public.LangCtx(ctx, "No log files found")))
		return res, nil
	}

	var collectedLines []string

	for _, file := range files {

		lines, readErr := readLines(file, "")
		if readErr != nil {
			continue
		}

		for j := len(lines) - 1; j >= 0; j-- {
			collectedLines = append(collectedLines, lines[j])

			if len(collectedLines) >= latestLogLinesLimit {
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

func getSortedLogFiles() ([]string, error) {
	logDir := public.AbsPath("../logs/core/out")
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}

	var fileNames []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".log") {
			fileNames = append(fileNames, entry.Name())
		}
	}

	if len(fileNames) == 0 {
		return nil, errors.New("no log files found")
	}

	sort.Sort(sort.Reverse(sort.StringSlice(fileNames)))

	var paths []string
	for _, file := range fileNames {
		paths = append(paths, filepath.Join(logDir, file))
	}

	return paths, nil
}
