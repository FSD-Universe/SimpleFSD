// Package service
// 存放 ControllerServiceInterface 的实现
package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
)

type ControllerService struct {
	logger                    log.LoggerInterface
	config                    *config.HttpServerConfig
	messageQueue              queue.MessageQueueInterface
	userOperation             operation.UserOperationInterface
	controllerOperation       operation.ControllerOperationInterface
	controllerRecordOperation operation.ControllerRecordOperationInterface
	auditLogOperation         operation.AuditLogOperationInterface
}

func NewControllerService(
	logger log.LoggerInterface,
	config *config.HttpServerConfig,
	messageQueue queue.MessageQueueInterface,
	userOperation operation.UserOperationInterface,
	controllerOperation operation.ControllerOperationInterface,
	controllerRecordOperation operation.ControllerRecordOperationInterface,
	auditLogOperation operation.AuditLogOperationInterface,
) *ControllerService {
	return &ControllerService{
		logger:                    log.NewLoggerAdapter(logger, "ControllerService"),
		config:                    config,
		messageQueue:              messageQueue,
		userOperation:             userOperation,
		controllerOperation:       controllerOperation,
		controllerRecordOperation: controllerRecordOperation,
		auditLogOperation:         auditLogOperation,
	}
}

func (controllerService *ControllerService) GetControllerList(req *RequestControllerList) *ApiResponse[ResponseControllerList] {
	if req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[ResponseControllerList](ErrIllegalParam, nil)
	}

	if res := CheckPermission[ResponseControllerList](req.Permission, operation.ControllerShowList); res != nil {
		return res
	}

	users, total, err := controllerService.controllerOperation.GetControllers(req.Page, req.PageSize)
	if res := CheckDatabaseError[ResponseControllerList](err); res != nil {
		return res
	}

	return NewApiResponse(SuccessGetControllers, &PageResponse[*operation.User]{
		Items:    users,
		Page:     req.Page,
		PageSize: req.PageSize,
		Total:    total,
	})
}

func (controllerService *ControllerService) GetCurrentControllerRecord(req *RequestGetCurrentControllerRecord) *ApiResponse[ResponseGetCurrentControllerRecord] {
	if req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[ResponseGetCurrentControllerRecord](ErrIllegalParam, nil)
	}

	records, total, err := controllerService.controllerRecordOperation.GetControllerRecords(req.Uid, req.Page, req.PageSize)
	if res := CheckDatabaseError[ResponseGetCurrentControllerRecord](err); res != nil {
		return res
	}

	return NewApiResponse(SuccessGetCurrentControllerRecord, &PageResponse[*operation.ControllerRecord]{
		Items:    records,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	})
}

func (controllerService *ControllerService) GetControllerRecord(req *RequestGetControllerRecord) *ApiResponse[ResponseGetControllerRecord] {
	if req.TargetUid <= 0 || req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[ResponseGetControllerRecord](ErrIllegalParam, nil)
	}

	if res := CheckPermission[ResponseGetControllerRecord](req.Permission, operation.ControllerShowRecord); res != nil {
		return res
	}

	records, total, err := controllerService.controllerRecordOperation.GetControllerRecords(req.TargetUid, req.Page, req.PageSize)
	if res := CheckDatabaseError[ResponseGetControllerRecord](err); res != nil {
		return res
	}

	return NewApiResponse(SuccessGetCurrentControllerRecord, &PageResponse[*operation.ControllerRecord]{
		Items:    records,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	})
}

func (controllerService *ControllerService) GetControllerRatings(req *RequestControllerRatingList) *ApiResponse[ResponseControllerRatingList] {
	if req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[ResponseControllerRatingList](ErrIllegalParam, nil)
	}

	users, total, err := controllerService.controllerOperation.GetControllers(req.Page, req.PageSize)
	if res := CheckDatabaseError[ResponseControllerRatingList](err); res != nil {
		return res
	}

	ratings := make([]*ControllerRating, 0)
	for _, user := range users {
		ratings = append(ratings, &ControllerRating{
			Cid:          user.Cid,
			Rating:       user.Rating,
			AvatarUrl:    user.AvatarUrl,
			UnderMonitor: user.UnderMonitor,
			UnderSolo:    user.UnderSolo,
			SoloUntil:    user.SoloUntil,
			Tier2:        user.Tier2,
			IsGuest:      user.Guest,
		})
	}

	return NewApiResponse(SuccessGetControllerRatings, &PageResponse[*ControllerRating]{
		Items:    ratings,
		Page:     req.Page,
		PageSize: req.PageSize,
		Total:    total,
	})
}

func (controllerService *ControllerService) UpdateControllerRating(req *RequestUpdateControllerRating) *ApiResponse[bool] {
	if req.TargetUid <= 0 || !fsd.IsValidRating(req.Rating) || (req.UnderSolo && (req.SoloUntil.IsZero() || req.SoloUntil.Before(time.Now()))) || (req.Guest && (req.UnderMonitor || req.UnderSolo)) {
		return NewApiResponse(ErrIllegalParam, false)
	}

	user, res := CallDBFunc[*operation.User, bool](func() (*operation.User, error) {
		return controllerService.userOperation.GetUserByUid(req.Uid)
	})
	if res != nil {
		return res
	}

	targetUser, res := CallDBFunc[*operation.User, bool](func() (*operation.User, error) {
		return controllerService.userOperation.GetUserByUid(req.TargetUid)
	})
	if res != nil {
		return res
	}

	updateInfo := make(map[string]interface{})

	if targetUser.Rating != req.Rating {
		if res := CheckPermission[bool](user.Permission, operation.ControllerEditRating); res != nil {
			return res
		}
		updateInfo["rating"] = req.Rating
	}

	if targetUser.UnderMonitor != req.UnderMonitor {
		if res := CheckPermission[bool](user.Permission, operation.ControllerChangeUnderMonitor); res != nil {
			return res
		}
		updateInfo["under_monitor"] = req.UnderMonitor
	}

	if targetUser.Guest != req.Guest {
		if res := CheckPermission[bool](user.Permission, operation.ControllerChangeGuest); res != nil {
			return res
		}
		updateInfo["guest"] = req.Guest
	}

	if targetUser.Tier2 != req.Tier2 {
		if res := CheckPermission[bool](user.Permission, operation.ControllerTier2Rating); res != nil {
			return res
		}
		updateInfo["tier2"] = req.Tier2
	}

	if targetUser.UnderSolo != req.UnderSolo || (targetUser.UnderSolo && targetUser.SoloUntil.Equal(req.SoloUntil)) {
		if res := CheckPermission[bool](user.Permission, operation.ControllerChangeSolo); res != nil {
			return res
		}
		updateInfo["under_solo"] = req.UnderSolo
		if req.UnderSolo {
			updateInfo["solo_until"] = req.SoloUntil
		} else {
			updateInfo["solo_until"] = time.UnixMicro(0)
		}
	}

	if len(updateInfo) == 0 {
		return NewApiResponse(ErrSameRating, false)
	}

	oldRatingStr := fsd.ToRatingString(targetUser.Rating, targetUser.Tier2, targetUser.UnderMonitor, targetUser.UnderSolo)

	if res := CallDBFuncWithoutRet[bool](func() error {
		return controllerService.controllerOperation.SetControllerRating(targetUser, updateInfo)
	}); res != nil {
		return res
	}

	newRatingStr := fsd.ToRatingString(req.Rating, targetUser.Tier2, req.UnderMonitor, req.UnderSolo)

	controllerService.messageQueue.Publish(&queue.Message{
		Type: queue.SendAtcRatingChangeEmail,
		Data: &interfaces.AtcRatingChangeEmailData{
			User:      targetUser,
			Operator:  user,
			OldRating: oldRatingStr,
			NewRating: newRatingStr,
		},
	})

	controllerService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: controllerService.auditLogOperation.NewAuditLog(
			operation.ControllerRatingChange,
			req.Cid,
			fmt.Sprintf("%04d", targetUser.Cid),
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: oldRatingStr,
				NewValue: newRatingStr,
			},
		),
	})

	return NewApiResponse(SuccessUpdateControllerRating, true)
}

func (controllerService *ControllerService) AddControllerRecord(req *RequestAddControllerRecord) *ApiResponse[bool] {
	if req.TargetUid <= 0 || req.Content == "" || !operation.IsValidControllerRecordType(req.Type) {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ControllerCreateRecord); res != nil {
		return res
	}

	targetUser, res := CallDBFunc[*operation.User, bool](func() (*operation.User, error) {
		return controllerService.userOperation.GetUserByUid(req.TargetUid)
	})
	if res != nil {
		return res
	}

	controllerRecordType := operation.ControllerRecordType(req.Type)

	record := controllerService.controllerRecordOperation.NewControllerRecord(req.TargetUid, req.Cid, controllerRecordType, req.Content)

	if res := CallDBFuncWithoutRet[bool](func() error {
		return controllerService.controllerRecordOperation.SaveControllerRecord(record)
	}); res != nil {
		return res
	}

	newValue, _ := json.Marshal(record)
	controllerService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: controllerService.auditLogOperation.NewAuditLog(
			operation.ControllerRecordCreated,
			req.Cid,
			fmt.Sprintf("%04d", targetUser.Cid),
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: operation.ValueNotAvailable,
				NewValue: string(newValue),
			},
		),
	})

	return NewApiResponse(SuccessAddControllerRecord, true)
}

func (controllerService *ControllerService) DeleteControllerRecord(req *RequestDeleteControllerRecord) *ApiResponse[bool] {
	if req.TargetRecord <= 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ControllerDeleteRecord); res != nil {
		return res
	}

	record, res := CallDBFunc[*operation.ControllerRecord, bool](func() (*operation.ControllerRecord, error) {
		return controllerService.controllerRecordOperation.GetControllerRecord(req.TargetRecord, req.TargetUid)
	})
	if res != nil {
		return res
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		return controllerService.controllerRecordOperation.DeleteControllerRecord(req.TargetRecord)
	}); res != nil {
		return res
	}

	oldValue, _ := json.Marshal(record)
	controllerService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: controllerService.auditLogOperation.NewAuditLog(
			operation.ControllerRecordDeleted,
			req.Cid,
			fmt.Sprintf("%d", req.TargetRecord),
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: string(oldValue),
				NewValue: operation.ValueNotAvailable,
			},
		),
	})

	return NewApiResponse(SuccessDeleteControllerRecord, true)
}
