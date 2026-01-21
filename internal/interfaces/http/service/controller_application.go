// Package service
package service

import (
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
)

var (
	ErrApplicationNotFound      = NewApiStatus("APPLICATION_NOT_FOUND", "未找到存在的申请", NotFound)
	ErrApplicationAlreadyExists = NewApiStatus("APPLICATION_ALREADY_EXISTS", "已有一个活动的管制员申请", Conflict)
	ErrStatusCantFallBack       = NewApiStatus("STATUS_CAN_NOT_FALLBACK", "状态无法回退", BadRequest)
	ErrSameApplicationStatus    = NewApiStatus("SAME_APPLICATION_STATUS", "相同的申请状态", BadRequest)
	SuccessGetSelfApplication   = NewApiStatus("GET_SELF_APPLICATION", "获取管制员申请成功", Ok)
	SuccessGetApplications      = NewApiStatus("GET_APPLICATIONS", "获取管制员申请列表成功", Ok)
	SuccessSubmitApplication    = NewApiStatus("SUBMIT_APPLICATION", "成功提交申请", Ok)
	SuccessCancelApplication    = NewApiStatus("CANCEL_APPLICATION", "成功取消申请", Ok)
	SuccessUpdateApplication    = NewApiStatus("UPDATE_APPLICATION", "成功更新申请", Ok)
)

type ControllerApplicationServiceInterface interface {
	GetSelfApplication(req *RequestGetSelfApplication) *ApiResponse[ResponseGetSelfApplication]
	GetApplications(req *RequestGetApplications) *ApiResponse[ResponseGetApplications]
	SubmitControllerApplication(req *RequestSubmitControllerApplication) *ApiResponse[bool]
	CancelSelfApplication(req *RequestCancelSelfApplication) *ApiResponse[bool]
	UpdateApplicationStatus(req *RequestUpdateApplicationStatus) *ApiResponse[bool]
}

type RequestGetSelfApplication struct {
	JwtHeader
}

type ResponseGetSelfApplication = *operation.ControllerApplication

type RequestGetApplications struct {
	JwtHeader
	PageArguments
}

type ResponseGetApplications = *PageResponse[*operation.ControllerApplication]

type RequestSubmitControllerApplication struct {
	JwtHeader
	EchoContentHeader
	*operation.ControllerApplication
}

type RequestCancelSelfApplication struct {
	JwtHeader
	EchoContentHeader
}

type RequestUpdateApplicationStatus struct {
	JwtHeader
	EchoContentHeader
	ApplicationId uint        `param:"aid"`
	Status        int         `json:"status"`
	AvailableTime []time.Time `json:"times"`
	Message       string      `json:"message"`
}
