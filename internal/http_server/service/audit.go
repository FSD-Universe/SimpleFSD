// Package service
// 存放 AuditServiceInterface 的实现
package service

import (
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
)

type AudioLogService struct {
	logger         log.LoggerInterface
	auditOperation operation.AuditLogOperationInterface
}

func NewAuditService(
	logger log.LoggerInterface,
	auditOperation operation.AuditLogOperationInterface,
) *AudioLogService {
	return &AudioLogService{
		logger:         log.NewLoggerAdapter(logger, "AudioLogService"),
		auditOperation: auditOperation,
	}
}

func (auditLogService *AudioLogService) HandleAuditLogMessage(message *queue.Message) error {
	if val, ok := message.Data.(*operation.AuditLog); ok {
		return auditLogService.auditOperation.SaveAuditLog(val)
	}
	return queue.ErrMessageDataType
}

func (auditLogService *AudioLogService) HandleAuditLogsMessage(message *queue.Message) error {
	if val, ok := message.Data.([]*operation.AuditLog); ok {
		return auditLogService.auditOperation.SaveAuditLogs(val)
	}
	return queue.ErrMessageDataType
}

func (auditLogService *AudioLogService) GetAuditLogPage(req *RequestGetAuditLog) *ApiResponse[ResponseGetAuditLog] {
	if req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[ResponseGetAuditLog](ErrIllegalParam, nil)
	}

	if res := CheckPermission[ResponseGetAuditLog](req.Permission, operation.AuditLogShow); res != nil {
		return res
	}

	auditLogs, total, err := auditLogService.auditOperation.GetAuditLogs(req.Page, req.PageSize)
	if res := CheckDatabaseError[ResponseGetAuditLog](err); res != nil {
		return res
	}

	return NewApiResponse(SuccessGetAuditLog, &PageResponse[*operation.AuditLog]{
		Items:    auditLogs,
		Page:     req.Page,
		PageSize: req.PageSize,
		Total:    total,
	})
}

func (auditLogService *AudioLogService) LogUnlawfulOverreach(req *RequestLogUnlawfulOverreach) *ApiResponse[bool] {
	auditLog := auditLogService.auditOperation.NewAuditLog(
		operation.UnlawfulOverreach,
		req.Cid,
		req.AccessPath,
		req.Ip,
		req.UserAgent,
		nil,
	)

	if err := auditLogService.auditOperation.SaveAuditLog(auditLog); err != nil {
		auditLogService.logger.ErrorF("Fail to create audit log for unlawful_overreach, detail: %v", err)
	}

	return NewApiResponse(SuccessLogUnlawfulOverreach, true)
}
