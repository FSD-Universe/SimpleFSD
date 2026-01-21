// Package service
package service

import (
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
)

var (
	ErrAnnouncementNotFound       = NewApiStatus("ANNOUNCEMENT_NOT_FOUND", "未找到公告", NotFound)
	SuccessGetAnnouncements       = NewApiStatus("GET_ANNOUNCEMENTS", "成功获取公告", Ok)
	SuccessGetDetailAnnouncements = NewApiStatus("GET_DETAIL_ANNOUNCEMENTS", "成功获取公告", Ok)
	SuccessPublishAnnouncement    = NewApiStatus("PUBLISH_ANNOUNCEMENT", "成功发布公告", Ok)
	SuccessEditAnnouncement       = NewApiStatus("EDIT_ANNOUNCEMENT", "成功编辑公告", Ok)
	SuccessDeleteAnnouncement     = NewApiStatus("DELETE_ANNOUNCEMENT", "成功删除公告", Ok)
)

type AnnouncementServiceInterface interface {
	GetAnnouncements(req *RequestGetAnnouncements) *ApiResponse[ResponseGetAnnouncements]
	GetDetailAnnouncements(req *RequestGetDetailAnnouncements) *ApiResponse[ResponseGetDetailAnnouncements]
	PublishAnnouncement(req *RequestPublishAnnouncement) *ApiResponse[bool]
	EditAnnouncement(req *RequestEditAnnouncement) *ApiResponse[bool]
	DeleteAnnouncement(req *RequestDeleteAnnouncement) *ApiResponse[bool]
}

type RequestGetAnnouncements struct {
	JwtHeader
	PageArguments
}

type ResponseGetAnnouncements = *PageResponse[*operation.UserAnnouncement]

type RequestGetDetailAnnouncements struct {
	JwtHeader
	PageArguments
}

type ResponseGetDetailAnnouncements = *PageResponse[*operation.Announcement]

type RequestPublishAnnouncement struct {
	JwtHeader
	EchoContentHeader
	*operation.Announcement
}

type RequestEditAnnouncement struct {
	JwtHeader
	EchoContentHeader
	AnnouncementId uint `param:"aid"`
	*operation.Announcement
}

type RequestDeleteAnnouncement struct {
	JwtHeader
	EchoContentHeader
	AnnouncementId uint `param:"aid"`
}
