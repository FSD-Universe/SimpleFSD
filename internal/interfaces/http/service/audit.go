// Package service
package service

import "github.com/half-nothing/simple-fsd/internal/interfaces/operation"

var (
	SuccessGetAuditLog          = NewApiStatus("GET_AUDIT_LOG", "成功获取审计日志", Ok)
	SuccessLogUnlawfulOverreach = NewApiStatus("LOG_UNLAWFUL_OVERREACH", "成功记录非法访问", Ok)
)

type AuditServiceInterface interface {
	GetAuditLogPage(req *RequestGetAuditLog) *ApiResponse[ResponseGetAuditLog]
	LogUnlawfulOverreach(req *RequestLogUnlawfulOverreach) *ApiResponse[bool]
}

type RequestGetAuditLog struct {
	JwtHeader
	PageArguments
}

type ResponseGetAuditLog = *PageResponse[*operation.AuditLog]

type RequestLogUnlawfulOverreach struct {
	JwtHeader
	EchoContentHeader
	AccessPath string `json:"access_path"`
}
