// Package service
// 存放 FlightPlanServiceInterface 的实现
package service

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type FlightPlanService struct {
	logger              log.LoggerInterface
	messageQueue        queue.MessageQueueInterface
	userOperation       operation.UserOperationInterface
	flightPlanOperation operation.FlightPlanOperationInterface
	auditLogOperation   operation.AuditLogOperationInterface
}

func NewFlightPlanService(
	logger log.LoggerInterface,
	messageQueue queue.MessageQueueInterface,
	userOperation operation.UserOperationInterface,
	flightPlanOperation operation.FlightPlanOperationInterface,
	auditLogOperation operation.AuditLogOperationInterface,
) *FlightPlanService {
	return &FlightPlanService{
		logger:              log.NewLoggerAdapter(logger, "FlightPlanService"),
		messageQueue:        messageQueue,
		userOperation:       userOperation,
		flightPlanOperation: flightPlanOperation,
		auditLogOperation:   auditLogOperation,
	}
}

func (flightPlanService *FlightPlanService) SubmitFlightPlan(req *RequestSubmitFlightPlan) *ApiResponse[bool] {
	if req.FlightPlan == nil {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if utils.ContainsChinese(req.FlightPlan.Route) ||
		utils.ContainsChinese(req.FlightPlan.Remarks) {
		return NewApiResponse(ErrChineseNotSupported, false)
	}

	if flightPlan, err := flightPlanService.flightPlanOperation.GetFlightPlanByCid(req.JwtHeader.Cid); err != nil {
		if errors.Is(err, operation.ErrFlightPlanNotFound) {
			req.FlightPlan.ID = 0
		} else {
			return NewApiResponse(ErrDatabaseFail, false)
		}
	} else {
		if flightPlan.Locked && flightPlan.DepartureAirport == req.DepartureAirport && flightPlan.ArrivalAirport == req.ArrivalAirport {
			return NewApiResponse(ErrFlightPlanLocked, false)
		}
		req.FlightPlan.Locked = false
		req.FlightPlan.ID = flightPlan.ID
		req.FlightPlan.CreatedAt = flightPlan.CreatedAt
	}

	req.FlightPlan.Cid = req.JwtHeader.Cid
	req.FlightPlan.FromWeb = true

	if res := CallDBFuncWithoutRet[bool](func() error {
		return flightPlanService.flightPlanOperation.SaveFlightPlan(req.FlightPlan)
	}); res != nil {
		return res
	}

	flightPlanService.messageQueue.Publish(&queue.Message{
		Type: queue.FlushFlightPlan,
		Data: &fsd.FlushFlightPlan{
			TargetCallsign: req.FlightPlan.Callsign,
			TargetCid:      req.JwtHeader.Cid,
			FlightPlan:     req.FlightPlan,
		},
	})

	return NewApiResponse(SuccessSubmitFlightPlan, true)
}

func (flightPlanService *FlightPlanService) GetFlightPlan(req *RequestGetFlightPlan) *ApiResponse[ResponseGetFlightPlan] {
	flightPlan, res := CallDBFunc[*operation.FlightPlan, ResponseGetFlightPlan](func() (*operation.FlightPlan, error) {
		return flightPlanService.flightPlanOperation.GetFlightPlanByCid(req.Cid)
	})
	if res != nil {
		return res
	}

	return NewApiResponse(SuccessGetFlightPlan, flightPlan)
}

func (flightPlanService *FlightPlanService) GetFlightPlans(req *RequestGetFlightPlans) *ApiResponse[ResponseGetFlightPlans] {
	if req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[ResponseGetFlightPlans](ErrIllegalParam, nil)
	}

	if res := CheckPermission[ResponseGetFlightPlans](req.Permission, operation.FlightPlanShowList); res != nil {
		return res
	}

	flightPlans, total, err := flightPlanService.flightPlanOperation.GetFlightPlans(req.Page, req.PageSize)
	if res := CheckDatabaseError[ResponseGetFlightPlans](err); res != nil {
		return res
	}

	return NewApiResponse(SuccessGetFlightPlans, &PageResponse[*operation.FlightPlan]{
		Items:    flightPlans,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	})
}

func (flightPlanService *FlightPlanService) DeleteSelfFlightPlan(req *RequestDeleteSelfFlightPlan) *ApiResponse[bool] {
	flightPlan, res := CallDBFunc[*operation.FlightPlan, bool](func() (*operation.FlightPlan, error) {
		return flightPlanService.flightPlanOperation.GetFlightPlanByCid(req.Cid)
	})
	if res != nil {
		return res
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		return flightPlanService.flightPlanOperation.DeleteSelfFlightPlan(flightPlan)
	}); res != nil {
		return res
	}

	flightPlanService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: flightPlanService.auditLogOperation.NewAuditLog(
			operation.FlightPlanSelfDeleted,
			req.Cid,
			fmt.Sprintf("%04d", req.Cid),
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	flightPlanService.messageQueue.Publish(&queue.Message{
		Type: queue.FlushFlightPlan,
		Data: &fsd.FlushFlightPlan{
			TargetCallsign: flightPlan.Callsign,
			TargetCid:      req.Cid,
			FlightPlan:     nil,
		},
	})

	return NewApiResponse(SuccessDeleteSelfFlightPlan, true)
}

func (flightPlanService *FlightPlanService) DeleteFlightPlan(req *RequestDeleteFlightPlan) *ApiResponse[bool] {
	if req.TargetCid <= 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.FlightPlanDelete); res != nil {
		return res
	}

	flightPlan, res := CallDBFunc[*operation.FlightPlan, bool](func() (*operation.FlightPlan, error) {
		return flightPlanService.flightPlanOperation.GetFlightPlanByCid(req.TargetCid)
	})
	if res != nil {
		return res
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		return flightPlanService.flightPlanOperation.DeleteFlightPlan(flightPlan)
	}); res != nil {
		return res
	}

	flightPlanService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: flightPlanService.auditLogOperation.NewAuditLog(
			operation.FlightPlanDeleted,
			req.Cid,
			fmt.Sprintf("%04d", req.TargetCid),
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	flightPlanService.messageQueue.Publish(&queue.Message{
		Type: queue.FlushFlightPlan,
		Data: &fsd.FlushFlightPlan{
			TargetCallsign: flightPlan.Callsign,
			TargetCid:      req.Cid,
			FlightPlan:     nil,
		},
	})

	return NewApiResponse(SuccessDeleteFlightPlan, true)
}

func (flightPlanService *FlightPlanService) LockFlightPlan(req *RequestLockFlightPlan) *ApiResponse[bool] {
	if req.TargetCid <= 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.FlightPlanChangeLock); res != nil {
		return res
	}

	flightPlan, res := CallDBFunc[*operation.FlightPlan, bool](func() (*operation.FlightPlan, error) {
		return flightPlanService.flightPlanOperation.GetFlightPlanByCid(req.TargetCid)
	})
	if res != nil {
		return res
	}

	if flightPlan.Locked == req.Lock {
		if req.Lock {
			return NewApiResponse(ErrFlightPlanLocked, false)
		}
		return NewApiResponse(ErrFlightPlanUnlocked, false)
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		if req.Lock {
			return flightPlanService.flightPlanOperation.LockFlightPlan(flightPlan)
		}
		return flightPlanService.flightPlanOperation.UnlockFlightPlan(flightPlan)
	}); res != nil {
		return res
	}

	flightPlanService.messageQueue.Publish(&queue.Message{
		Type: queue.ChangeFlightPlanLockStatus,
		Data: &fsd.LockChange{
			TargetCallsign: flightPlan.Callsign,
			TargetCid:      req.Cid,
			Locked:         req.Lock,
		},
	})

	var auditLogType operation.AuditEventType
	if req.Lock {
		auditLogType = operation.FlightPlanLock
	} else {
		auditLogType = operation.FlightPlanUnlock
	}

	flightPlanService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: flightPlanService.auditLogOperation.NewAuditLog(
			auditLogType,
			req.Cid,
			fmt.Sprintf("%04d", req.TargetCid),
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: strconv.FormatBool(!req.Lock),
				NewValue: strconv.FormatBool(req.Lock),
			},
		),
	})

	return NewApiResponse(SuccessLockFlightPlan, true)
}
