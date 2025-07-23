package askai

import (
	v1 "billionmail-core/api/askai/v1"
	"billionmail-core/internal/service/askai"
	"billionmail-core/internal/service/public"
	"billionmail-core/utility/types/api_v1"
	"context"
	"errors"
)

func (c *ControllerV1) List(ctx context.Context, req *v1.ListReq) (res *v1.ListRes, err error) {
	res = &v1.ListRes{}
	res.Data = askai.List()
	if res.Data == nil {
		res.SetError(errors.New(public.LangCtx(ctx, "Not suppliers found")))
		return res, nil
	}
	res.SetSuccess(public.LangCtx(ctx, "List of suppliers retrieved successfully"))
	return res, nil
}

func (c *ControllerV1) Models(ctx context.Context, req *v1.ModelsReq) (res *v1.ModelsRes, err error) {
	res = &v1.ModelsRes{}
	res.Data = askai.Models(req.SupplierName)
	res.SetSuccess(public.LangCtx(ctx, "List of models retrieved successfully"))
	return res, nil
}

func (c *ControllerV1) AddModel(ctx context.Context, req *v1.AddModelReq) (res *v1.AddModelRes, err error) {
	res = &v1.AddModelRes{}
	res.Data = askai.AddModel(req.SupplierName, req.Title, req.ModelId, req.MaxTokens, req.Capability)
	res.SetSuccess(public.LangCtx(ctx, "Model added successfully"))
	return res, nil
}

func (c *ControllerV1) RemoveModel(ctx context.Context, req *v1.RemoveModelReq) (res *v1.RemoveModelRes, err error) {
	res = &v1.RemoveModelRes{}
	res.Data = askai.RemoveModel(req.SupplierName, req.ModelId)
	if res.Data == nil {
		res.SetError(errors.New(public.LangCtx(ctx, "Model not found")))
		return res, nil
	}
	res.SetSuccess(public.LangCtx(ctx, "Model removed successfully"))
	return res, nil
}

func (c *ControllerV1) SetSupplierConfig(ctx context.Context, req *v1.SetSupplierConfigReq) (res *api_v1.StandardRes, err error) {
	res = &api_v1.StandardRes{}
	result := askai.SetSupplierConfig(req.SupplierName, req.BaseUrl, req.ApiKey)
	if result == nil {
		res.Data = result
		res.SetSuccess(public.LangCtx(ctx, "Supplier configuration updated successfully"))
	} else {
		res.SetError(result)
	}

	return res, nil
}

func (c *ControllerV1) Testing(ctx context.Context, req *v1.TestingReq) (res *v1.TestingRes, err error) {
	res = &v1.TestingRes{}
	err = askai.Testing(req.SupplierName, req.BaseUrl, req.ApiKey)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Supplier connection successful"))
	}

	// fmt.Println("Testing supplier connection:%s", req.SupplierName)
	return res, nil
}

func (c *ControllerV1) GetSupplierConfig(ctx context.Context, req *v1.GetSupplierConfigReq) (res *v1.GetSupplierConfigRes, err error) {
	res = &v1.GetSupplierConfigRes{}
	config, err := askai.GetSupplierConfig(req.SupplierName)
	if err == nil {
		res.Data = config
		res.SetSuccess(public.LangCtx(ctx, "Supplier configuration retrieved successfully"))
	} else {
		res.SetError(err)
	}
	return res, nil
}

func (c *ControllerV1) SetSupplierStatus(ctx context.Context, req *v1.SetSupplierStatusReq) (res *api_v1.StandardRes, err error) {
	res = &api_v1.StandardRes{}
	err = askai.SetSupplierStatus(req.SupplierName, req.Status)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Supplier status updated successfully"))
	}

	return res, nil
}

func (c *ControllerV1) SetModelStatus(ctx context.Context, req *v1.SetModelStatusReq) (res *api_v1.StandardRes, err error) {
	res = &api_v1.StandardRes{}
	err = askai.SetModelStatus(req.SupplierName, req.ModelId, req.Status)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Model status updated successfully"))
	}

	return res, nil
}

func (c *ControllerV1) AddSupplier(ctx context.Context, req *v1.AddSupplierReq) (res *v1.AddSupplierRes, err error) {
	res = &v1.AddSupplierRes{}
	err = askai.AddSupplier(req.SupplierTitle, req.SupplierName, req.BaseUrl, req.ApiKey)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Supplier added successfully"))
	}
	return res, nil
}

func (c *ControllerV1) RemoveSupplier(ctx context.Context, req *v1.RemoveSupplierReq) (res *v1.RemoveSupplierRes, err error) {
	res = &v1.RemoveSupplierRes{}
	err = askai.RemoveSupplier(req.SupplierName)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Supplier removed successfully"))
	}
	return res, nil
}
func (c *ControllerV1) SetModelTitle(ctx context.Context, req *v1.SetModelTitleReq) (res *v1.SetModelTitleRes, err error) {
	res = &v1.SetModelTitleRes{}
	err = askai.SetModelTitle(req.SupplierName, req.ModelId, req.Title)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Model title updated successfully"))
	}
	return res, nil
}

func (c *ControllerV1) SetModelCapability(ctx context.Context, req *v1.SetModelCapabilityReq) (res *v1.SetModelCapabilityRes, err error) {
	res = &v1.SetModelCapabilityRes{}
	err = askai.SetModelCapability(req.SupplierName, req.ModelId, req.Capability)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Model capability updated successfully"))
	}
	return res, nil
}

func (c *ControllerV1) ModifyModel(ctx context.Context, req *v1.ModifyModelReq) (res *v1.ModifyModelRes, err error) {
	res = &v1.ModifyModelRes{}
	err = askai.ModifyModel(req.SupplierName, req.ModelId, req.MaxTokens, req.Capability, req.Title)
	if err != nil {
		res.SetError(err)
	} else {
		res.SetSuccess(public.LangCtx(ctx, "Model modified successfully"))
	}
	return res, nil
}

func (c *ControllerV1) Status(ctx context.Context, req *v1.StatusReq) (res *v1.StatusRes, err error) {
	res = &v1.StatusRes{}
	status := askai.Status()
	if err != nil {
		res.SetError(err)
	} else {
		res.Data = map[string]bool{
			"is_configured": status,
		}
		res.SetSuccess(public.LangCtx(ctx, "Supplier status retrieved successfully"))
	}
	return res, nil
}
