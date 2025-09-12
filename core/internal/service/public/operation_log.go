package public

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gfile"
	"path/filepath"
	"time"
)

const snapshotBase = "../logs/core/operation_log"

func writeSnapshotFile(logType string, userID int64, data interface{}) (string, error) {
	dateDir := time.Now().Format("2006-01-02")
	dir := filepath.Join(AbsPath(snapshotBase), dateDir)
	if err := gfile.Mkdir(dir); err != nil {
		return "", err
	}
	ts := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%d_%s_%s.json", logType, userID, ts, RandomStr(5))
	path := filepath.Join(dir, filename)
	content, _ := json.MarshalIndent(data, "", "  ")
	if err := gfile.PutBytes(path, content); err != nil {
		return "", err
	}
	return path, nil
}

type LogParams struct {
	UserID int64
	Type   string
	Log    string
	IP     string
	Data   interface{}
}

func GetCurrentAccountId(ctx context.Context) int64 {
	value := ctx.Value("accountId")
	if value == nil {
		return 0
	}
	accountId, ok := value.(int64)
	if !ok {
		return 0
	}
	return accountId
}

func WriteLog(ctx context.Context, params LogParams) error {

	userId := GetCurrentAccountId(ctx)
	req := ghttp.RequestFromCtx(ctx)
	ip := ""
	if req != nil {
		ip = req.GetClientIp()
	}
	filePath := ""
	if params.Data != nil && params.Data != "" {
		filePath, _ = writeSnapshotFile(params.Type, int64(userId), params.Data)
	}

	_, err := g.DB().Model("bm_operation_logs").Data(g.Map{
		"user_id": userId,
		"type":    params.Type,
		"log":     params.Log,
		"ip":      ip,
		"info":    filePath,
		"addtime": time.Now().Unix(),
	}).InsertIgnore()
	return err
}
