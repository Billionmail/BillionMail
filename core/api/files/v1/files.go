package v1

import (
	"billionmail-core/utility/types/api_v1"
	"github.com/gogf/gf/v2/frame/g"
)

// DownloadFileReq File download request
type DownloadFileReq struct {
	g.Meta        `path:"/file/download" method:"get" tags:"Files" summary:"Download file by path"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header" v:"required"`
	FilePath      string `json:"file_path"    v:"required" dc:"File path for download"`
}

// DownloadFileRes File download response
type DownloadFileRes struct {
	api_v1.StandardRes
}

type ReadFileReq struct {
	g.Meta        `path:"/file/read" method:"get" tags:"Files" summary:"Read file by path"`
	Authorization string `json:"authorization" dc:"Authorization" in:"header" v:"required"`
	FilePath      string `json:"file_path"    v:"required" dc:"File path for read"`
}

// ReadFileRes File read response
type ReadFileRes struct {
	api_v1.StandardRes
}
