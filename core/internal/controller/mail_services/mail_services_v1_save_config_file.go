package mail_services

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"billionmail-core/api/mail_services/v1"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"
)

func (c *ControllerV1) SaveConfigFile(ctx context.Context, req *v1.SaveConfigFileReq) (res *v1.SaveConfigFileRes, err error) {
	res = &v1.SaveConfigFileRes{}

	var configPath string
	serviceType := strings.ToLower(req.ServiceType)
	switch {
	case strings.Contains(serviceType, "dovecot"):
		configPath = v1.ServiceType_Dovecot
	case strings.Contains(serviceType, "postfix"):
		configPath = v1.ServiceType_Postfix
	case strings.Contains(serviceType, "rspamd"):
		configPath = v1.ServiceType_Rspamd
	default:
		res.SetError(gerror.New(public.LangCtx(ctx, "Invalid service type")))
		return nil, err
	}

	dirPath := filepath.Dir(configPath)
	if !gfile.Exists(dirPath) {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Failed to create directory: {}", err.Error())))
			return nil, err
		}
	}

	var backupPath string
	backupMade := false
	if gfile.Exists(configPath) {
		backupPath = configPath + ".bak." + time.Now().Format("20060102150405")
		if err := gfile.Copy(configPath, backupPath); err != nil {
			g.Log().Debugf(ctx, "Failed to back up configuration file %s: %v", configPath, err)
		} else {
			g.Log().Infof(ctx, "A configuration file backup has been created: %s", backupPath)
			backupMade = true
		}
	}

	contentBytes := []byte(req.Content)
	if err := os.WriteFile(configPath, contentBytes, 0644); err != nil {
		if backupMade {
			err = gfile.Move(backupPath, configPath)
		}
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to save file: {}", err.Error())))
		return nil, err
	}

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Service,
		Log:  "The" + req.ServiceType + " configuration file was saved successfully",
		Data: req,
	})

	res.SetSuccess(public.LangCtx(ctx, "The configuration file was saved successfully"))
	return
}
