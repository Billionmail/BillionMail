package contact

import (
	"billionmail-core/api/contact/v1"
	"billionmail-core/internal/consts"
	"billionmail-core/internal/model/entity"
	"billionmail-core/internal/service/public"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"strings"
)

func (c *ControllerV1) EditContactsNDP(ctx context.Context, req *v1.EditContactsNDPReq) (res *v1.EditContactsNDPRes, err error) {
	res = &v1.EditContactsNDPRes{}

	if req.Id <= 0 {
		res.SetError(gerror.New(public.LangCtx(ctx, "The Id field is required")))
		return
	}

	var attribs map[string]string
	if req.Attribs != "" {
		attribsStr := strings.Trim(req.Attribs, "\"")
		attribsStr = strings.ReplaceAll(attribsStr, "\"\"", "\"")
		var rawAttribs map[string]interface{}
		if err = json.Unmarshal([]byte(attribsStr), &rawAttribs); err != nil {
			res.SetError(gerror.New(public.LangCtx(ctx, "Invalid attributes format: {}", err.Error())))
			return
		}
		attribs = make(map[string]string)
		for k, v := range rawAttribs {
			switch val := v.(type) {
			case string:
				attribs[k] = val
			case float64:
				if float64(int64(val)) == val {
					attribs[k] = fmt.Sprintf("%d", int64(val))
				} else {
					attribs[k] = fmt.Sprintf("%g", val)
				}
			case bool:
				attribs[k] = fmt.Sprintf("%v", val)
			case nil:
				attribs[k] = ""
			default:
				if bytes, err := json.Marshal(val); err == nil {
					attribs[k] = string(bytes)
				} else {
					attribs[k] = fmt.Sprintf("%v", val)
				}
			}
		}
	}

	updateData := make(map[string]interface{})
	err = g.DB().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {

		if req.Active != 0 && req.Active != 1 {
			// 不修改active
		} else {
			updateData["active"] = req.Active
		}
		if req.Status != 0 && req.Status != 1 {
			// 不修改status
		} else {
			updateData["status"] = req.Status
		}
		if attribs != nil {
			updateData["attribs"] = attribs
		}
		if len(updateData) == 0 {
			return gerror.New(public.LangCtx(ctx, "No valid fields to update"))
		}
		_, err = g.DB().Model("bm_contacts").Where("id", req.Id).Data(updateData).Update()
		if err != nil {
			return gerror.New(public.LangCtx(ctx, "Failed to update contact: {}", err.Error()))
		}
		return nil
	})

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to edit contact: {}", err.Error())))
		return
	}

	var contact entity.Contact
	err = g.DB().Model("bm_contacts").Where("id", req.Id).Scan(&contact)
	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Contacts,
		Log:  fmt.Sprintf("Edit contact: %s successfully", contact.Email),
		Data: contact,
	})
	res.SetSuccess(public.LangCtx(ctx, "Contact updated successfully"))
	return
}
