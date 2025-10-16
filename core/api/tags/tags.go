// =================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package tags

import (
	"context"

	"billionmail-core/api/tags/v1"
)

type ITagsV1 interface {
	TagList(ctx context.Context, req *v1.TagListReq) (res *v1.TagListRes, err error)
	TagCreate(ctx context.Context, req *v1.TagCreateReq) (res *v1.TagCreateRes, err error)
	TagUpdate(ctx context.Context, req *v1.TagUpdateReq) (res *v1.TagUpdateRes, err error)
	TagDelete(ctx context.Context, req *v1.TagDeleteReq) (res *v1.TagDeleteRes, err error)
	BatchTagContacts(ctx context.Context, req *v1.BatchTagContactsReq) (res *v1.BatchTagContactsRes, err error)
	TagAll(ctx context.Context, req *v1.TagAllReq) (res *v1.TagAllRes, err error)
}
