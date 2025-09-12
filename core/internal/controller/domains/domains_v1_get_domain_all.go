package domains

import (
	"billionmail-core/internal/service/domains"
	"billionmail-core/internal/service/public"
	"context"
	"fmt"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"

	"billionmail-core/api/domains/v1"
)

func (c *ControllerV1) GetDomainAll(ctx context.Context, req *v1.GetDomainAllReq) (res *v1.GetDomainAllRes, err error) {
	res = &v1.GetDomainAllRes{}

	res.Data, err = domains.All(ctx)

	if err != nil {
		res.SetError(fmt.Errorf("failed to get all domains: %w", gerror.NewCode(gcode.CodeInternalError, err.Error())))
		return
	}

	res.SetSuccess(public.LangCtx(ctx, "Success"))
	return
}
