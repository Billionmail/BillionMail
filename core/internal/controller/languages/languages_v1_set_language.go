package languages

import (
	"billionmail-core/internal/consts"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"strings"

	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/languages/v1"
)

func (c *ControllerV1) SetLanguage(ctx context.Context, req *v1.SetLanguageReq) (res *v1.SetLanguageRes, err error) {

	res = &v1.SetLanguageRes{}

	lang := strings.TrimSpace(req.Language)

	languageList := public.GetLanguageList()
	isValidLanguage := false

	//g.Log().Debug(ctx, "Available languages:", languageList)

	for _, langInfo := range languageList {
		if langCode, ok := langInfo["name"].(string); ok && langCode == lang {
			isValidLanguage = true
			break
		}
	}

	if !isValidLanguage {
		res.SetError(gerror.New(public.LangCtx(ctx, "Invalid language code: {}", lang)))
		return
	}

	val, err := g.DB().Model("bm_options").
		Where("name", "CurrentLanguage").
		Value("value")

	if err != nil && !g.IsNil(err) {
		g.Log().Error(ctx, "Failed to query language setting:", err)
		res.SetError(gerror.New(public.LangCtx(ctx, "Failed to query language setting: {}", err.Error())))
		return
	}

	if val != nil && val.String() != "" {

		_, err = g.DB().Model("bm_options").
			Where("name", "CurrentLanguage").
			Data(g.Map{"value": lang}).
			Update()
	} else {

		_, err = g.DB().Model("bm_options").
			Data(g.Map{
				"name":  "CurrentLanguage",
				"value": lang,
			}).Insert()
	}

	if err != nil {
		res.SetError(gerror.New(public.LangCtx(ctx, "Setup failure: {}", err.Error())))
		return
	}

	// update the session
	r := g.RequestFromCtx(ctx)
	if r != nil {
		r.Session.Set("language", lang)
	}

	// update the cache
	public.SetCache("language", lang, 3600)

	_ = public.WriteLog(ctx, public.LogParams{
		Type: consts.LOGTYPE.Contacts,
		Log:  fmt.Sprintf("Language changed to: %s ", lang),
	})

	res.SetSuccess(public.LangCtx(ctx, "Setup successful"))
	return
}
