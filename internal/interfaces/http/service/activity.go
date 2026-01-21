// Package service
package service

import (
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
)

type ActivityModel struct {
	Id         uint   `json:"id"`
	Publisher  int    `json:"publisher"`
	Title      string `json:"title"`
	ImageUrl   string `json:"image_url"`
	ActiveTime string `json:"active_time"`
	Departure  string `json:"departure"`
	Arrival    string `json:"arrival"`
	Route      string `json:"route"`
	Distance   int    `json:"distance"`
	Status     int    `json:"status"`
	NOTAMS     string `json:"notams"`
}

var (
	ErrActivityLocked         = NewApiStatus("ACTIVITY_LOCKED", "活动报名信息已锁定", Conflict)
	ErrActivityIdMismatch     = NewApiStatus("ACTIVITY_ID_MISMATCH", "活动ID不正确", Conflict)
	ErrActivityNotFound       = NewApiStatus("ACTIVITY_NOT_FOUND", "活动不存在", NotFound)
	ErrFacilityNotFound       = NewApiStatus("FACILITY_NOT_FOUND", "管制席位不存在", NotFound)
	ErrParseTime              = NewApiStatus("TIME_FORMAT_ERROR", "格式错误", BadRequest)
	ErrRatingTooLow           = NewApiStatus("RATING_TOO_LOW", "管制权限不够", PermissionDenied)
	ErrFacilityAlreadyExist   = NewApiStatus("FACILITY_ALREADY_EXIST", "你不能同时报名两个以上的席位", Conflict)
	ErrFacilityAlreadySigned  = NewApiStatus("FACILITY_ALREADY_SIGNED", "已有其他管制员报名", Conflict)
	ErrFacilityUnSigned       = NewApiStatus("FACILITY_UNSIGNED", "该席位尚未有人报名", Conflict)
	ErrFacilityNotYourSign    = NewApiStatus("FACILITY_NOT_YOUR_SIGN", "这不是你报名的席位", Conflict)
	ErrAlreadySigned          = NewApiStatus("ALREADY_SIGNED", "你已经报名该活动了", Conflict)
	ErrCallsignUsed           = NewApiStatus("CALLSIGN_USED", "呼号已被占用", Conflict)
	ErrNoSigned               = NewApiStatus("NO_SIGNED", "你还没有报名该活动", Conflict)
	SuccessGetActivities      = NewApiStatus("GET_ACTIVITIES", "成功获取活动", Ok)
	SuccessGetActivitiesPage  = NewApiStatus("GET_ACTIVITIES_PAGE", "成功获取活动分页", Ok)
	SuccessGetActivityInfo    = NewApiStatus("GET_ACTIVITY_INFO", "成功获取活动信息", Ok)
	SuccessAddActivity        = NewApiStatus("ADD_ACTIVITY", "成功添加活动", Ok)
	SuccessDeleteActivity     = NewApiStatus("DELETE_ACTIVITY", "成功删除活动", Ok)
	SuccessSignFacility       = NewApiStatus("SIGNED_FACILITY", "报名成功", Ok)
	SuccessUnsignFacility     = NewApiStatus("UNSIGNED_FACILITY", "成功取消报名", Ok)
	SuccessSignedActivity     = NewApiStatus("SIGNED_ACTIVITY", "报名成功", Ok)
	SuccessUnsignedActivity   = NewApiStatus("UNSIGNED_ACTIVITY", "取消报名成功", Ok)
	SuccessEditActivity       = NewApiStatus("EDIT_ACTIVITY", "修改活动成功", Ok)
	SuccessEditActivityStatus = NewApiStatus("EDIT_ACTIVITY_STATUS", "成功修改活动状态", Ok)
	SuccessEditPilotsStatus   = NewApiStatus("EDIT_PILOTS_STATUS", "成功修改活动机组状态", Ok)
)

type ActivityServiceInterface interface {
	GetActivities(req *RequestGetActivities) *ApiResponse[[]*operation.Activity]
	GetActivitiesPage(req *RequestGetActivitiesPage) *ApiResponse[*PageResponse[*operation.Activity]]
	GetActivityInfo(req *RequestActivityInfo) *ApiResponse[*operation.Activity]
	AddActivity(req *RequestAddActivity) *ApiResponse[bool]
	DeleteActivity(req *RequestDeleteActivity) *ApiResponse[bool]
	ControllerJoin(req *RequestControllerJoin) *ApiResponse[bool]
	ControllerLeave(req *RequestControllerLeave) *ApiResponse[bool]
	PilotJoin(req *RequestPilotJoin) *ApiResponse[bool]
	PilotLeave(req *RequestPilotLeave) *ApiResponse[bool]
	EditActivity(req *RequestEditActivity) *ApiResponse[bool]
	EditPilotStatus(req *RequestEditPilotStatus) *ApiResponse[bool]
	EditActivityStatus(req *RequestEditActivityStatus) *ApiResponse[bool]
}

type RequestGetActivities struct {
	Time string `query:"time"`
}

type RequestGetActivitiesPage struct {
	JwtHeader
	PageArguments
}

type RequestActivityInfo struct {
	ActivityId uint `param:"activity_id"`
}

type RequestAddActivity struct {
	JwtHeader
	EchoContentHeader
	*operation.Activity
}

type RequestDeleteActivity struct {
	JwtHeader
	EchoContentHeader
	ActivityId uint `param:"activity_id"`
}

type RequestControllerJoin struct {
	JwtHeader
	ActivityId uint `param:"activity_id"`
	FacilityId uint `param:"facility_id"`
}

type RequestControllerLeave struct {
	JwtHeader
	ActivityId uint `param:"activity_id"`
	FacilityId uint `param:"facility_id"`
}

type RequestPilotJoin struct {
	JwtHeader
	ActivityId   uint   `param:"activity_id"`
	Callsign     string `json:"callsign"`
	AircraftType string `json:"aircraft_type"`
}

type RequestPilotLeave struct {
	JwtHeader
	ActivityId uint `param:"activity_id"`
}

type RequestEditActivity struct {
	JwtHeader
	EchoContentHeader
	*operation.Activity
}

type RequestEditActivityStatus struct {
	JwtHeader
	ActivityId uint `param:"activity_id"`
	Status     int  `json:"status"`
}

type RequestEditPilotStatus struct {
	JwtHeader
	ActivityId uint `param:"activity_id"`
	UserId     uint `param:"user_id"`
	Status     int  `json:"status"`
}
