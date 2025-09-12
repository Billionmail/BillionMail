package v1

import (
	"billionmail-core/utility/types/api_v1"

	"github.com/gogf/gf/v2/frame/g"
)

// ListReq is the request structure for listing AI model suppliers.
type ListReq struct {
	g.Meta `path:"/askai/supplier/list" method:"get,post" tags:"AskAi" summary:"list ai models supplier"`
}

type ListRes struct {
	api_v1.StandardRes
}

// ModelsReq is the request structure for listing AI models of a specific supplier.
type ModelsReq struct {
	g.Meta       `path:"/askai/supplier/models" method:"get,post" tags:"AskAi" summary:"list ai models"`
	SupplierName string `json:"supplier_name" dc:"supplier name"`
}

type ModelsRes struct {
	api_v1.StandardRes
}

// AddModelReq is the request structure for adding a new AI model to a supplier.
type AddModelReq struct {
	g.Meta       `path:"/askai/supplier/add_model" method:"post" tags:"AskAi" summary:"add ai model"`
	SupplierName string   `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	Title        string   `json:"title" dc:"model title" v:"required#model title is required"`
	ModelId      string   `json:"model_id" dc:"model id" v:"required#model id is required"`
	MaxTokens    int      `json:"max_tokens" dc:"max tokens" v:"required#max tokens is required"`
	Capability   []string `json:"capability" dc:"capability" v:"required#capability is required"`
}

type AddModelRes struct {
	api_v1.StandardRes
}

// RemoveModelReq is the request structure for removing an AI model from a supplier.
type RemoveModelReq struct {
	g.Meta       `path:"/askai/supplier/remove_model" method:"post" tags:"AskAi" summary:"remove ai model"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	ModelId      string `json:"model_id" dc:"model id" v:"required#model id is required"`
}

type RemoveModelRes struct {
	api_v1.StandardRes
}

// SetSupplierConfigReq is the request structure for setting the configuration of an AI model supplier.
type SetSupplierConfigReq struct {
	g.Meta       `path:"/askai/supplier/set_supplier_config" method:"post" tags:"AskAi" summary:"set supplier config"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	BaseUrl      string `json:"base_url" dc:"base url" v:"required#base url is required"`
	ApiKey       string `json:"api_key" dc:"api key" v:"required#api key is required"`
}

type SetSupplierConfigRes struct {
	api_v1.StandardRes
}

// TestingReq is the request structure for testing the configuration of an AI model supplier.
type TestingReq struct {
	g.Meta       `path:"/askai/supplier/testing" method:"post" tags:"AskAi" summary:"test supplier config"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	BaseUrl      string `json:"base_url" dc:"base url" v:"required#base url is required"`
	ApiKey       string `json:"api_key" dc:"api key" v:"required#api key is required"`
}
type TestingRes struct {
	api_v1.StandardRes
}

// GetSupplierConfigReq is the request structure for retrieving the configuration of an AI model supplier.
type GetSupplierConfigReq struct {
	g.Meta       `path:"/askai/supplier/get_supplier_config" method:"post" tags:"AskAi" summary:"get supplier config"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
}

type GetSupplierConfigRes struct {
	api_v1.StandardRes
}

// SetSupplierStatusReq is the request structure for setting the status of an AI model supplier.
type SetSupplierStatusReq struct {
	g.Meta       `path:"/askai/supplier/set_supplier_status" method:"post" tags:"AskAi" summary:"set supplier status"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	Status       bool   `json:"status" dc:"status" v:"required#status is required"`
}

type SetSupplierStatusRes struct {
	api_v1.StandardRes
}

// SetModelStatusReq is the request structure for setting the status of an AI model.
type SetModelStatusReq struct {
	g.Meta       `path:"/askai/supplier/set_model_status" method:"post" tags:"AskAi" summary:"set model status"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	ModelId      string `json:"model_id" dc:"model id" v:"required#model id is required"`
	Status       bool   `json:"status" dc:"status" v:"required#status is required"`
}
type SetModelStatusRes struct {
	api_v1.StandardRes
}

// AddSupplierReq is the request structure for adding a new AI supplier.
type AddSupplierReq struct {
	g.Meta        `path:"/askai/supplier/add_supplier" method:"post" tags:"AskAi" summary:"add ai supplier"`
	SupplierTitle string `json:"supplier_title" dc:"supplier title" v:"required#supplier title is required"`
	SupplierName  string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	BaseUrl       string `json:"base_url" dc:"base url" v:"required#base url is required"`
	ApiKey        string `json:"api_key" dc:"api key" v:"required#api key is required"`
}

type AddSupplierRes struct {
	api_v1.StandardRes
}

// RemoveSupplierReq is the request structure for removing an AI supplier.
type RemoveSupplierReq struct {
	g.Meta       `path:"/askai/supplier/remove_supplier" method:"post" tags:"AskAi" summary:"remove ai supplier"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
}

type RemoveSupplierRes struct {
	api_v1.StandardRes
}

// SetModelTitleReq is the request structure for setting the title of an AI model.
type SetModelTitleReq struct {
	g.Meta       `path:"/askai/supplier/set_model_title" method:"post" tags:"AskAi" summary:"set model title"`
	SupplierName string `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	ModelId      string `json:"model_id" dc:"model id" v:"required#model id is required"`
	Title        string `json:"title" dc:"title" v:"required#title is required"`
}

type SetModelTitleRes struct {
	api_v1.StandardRes
}

// SetModelCapabilityReq is the request structure for setting the capabilities of an AI model.
type SetModelCapabilityReq struct {
	g.Meta       `path:"/askai/supplier/set_model_capability" method:"post" tags:"AskAi" summary:"set model capability"`
	SupplierName string   `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	ModelId      string   `json:"model_id" dc:"model id" v:"required#model id is required"`
	Capability   []string `json:"capability" dc:"capability" v:"required#capability is required" d:"llm,vision,tools,text-to-image"`
}
type SetModelCapabilityRes struct {
	api_v1.StandardRes
}

// ModifyModelReq is the request structure for modifying an AI model's details.
type ModifyModelReq struct {
	g.Meta       `path:"/askai/supplier/modify_model" method:"post" tags:"AskAi" summary:"modify model"`
	SupplierName string   `json:"supplier_name" dc:"supplier name" v:"required#supplier name is required"`
	ModelId      string   `json:"model_id" dc:"model id" v:"required#model id is required"`
	MaxTokens    int      `json:"max_tokens" dc:"max tokens" v:"required#max tokens is required"`
	Capability   []string `json:"capability" dc:"capability" v:"required#capability is required" d:"llm,vision,tools,text-to-image"`
	Title        string   `json:"title" dc:"title" v:"required#title is required"`
}

type ModifyModelRes struct {
	api_v1.StandardRes
}

// StatusReq is the request structure for retrieving the status of an AI model supplier's configuration.
type StatusReq struct {
	g.Meta `path:"/askai/supplier/status" method:"get,post" tags:"AskAi" summary:"get supplier config status"`
}
type StatusRes struct {
	api_v1.StandardRes
}
