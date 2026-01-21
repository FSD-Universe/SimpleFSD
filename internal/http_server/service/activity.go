// Package service
// 存放 ActivityServiceInterface 的实现
package service

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
)

type ActivityService struct {
	logger            log.LoggerInterface
	config            *config.HttpServerConfig
	messageQueue      queue.MessageQueueInterface
	userOperation     operation.UserOperationInterface
	activityOperation operation.ActivityOperationInterface
	storeService      StoreServiceInterface
	auditLogOperation operation.AuditLogOperationInterface
}

func NewActivityService(
	logger log.LoggerInterface,
	config *config.HttpServerConfig,
	messageQueue queue.MessageQueueInterface,
	userOperation operation.UserOperationInterface,
	activityOperation operation.ActivityOperationInterface,
	auditLogOperation operation.AuditLogOperationInterface,
	storeService StoreServiceInterface,
) *ActivityService {
	return &ActivityService{
		logger:            log.NewLoggerAdapter(logger, "ActivityService"),
		config:            config,
		messageQueue:      messageQueue,
		userOperation:     userOperation,
		activityOperation: activityOperation,
		storeService:      storeService,
		auditLogOperation: auditLogOperation,
	}
}

func (activityService *ActivityService) GetActivities(req *RequestGetActivities) *ApiResponse[[]*operation.Activity] {
	targetMonth, err := time.Parse("2006-01", req.Time)
	if err != nil {
		return NewApiResponse[[]*operation.Activity](ErrParseTime, nil)
	}
	firstDay := targetMonth.AddDate(0, -1, 0)
	lastDay := targetMonth.AddDate(0, 2, 0).Add(-time.Second)
	activities, res := CallDBFunc[[]*operation.Activity, []*operation.Activity](func() ([]*operation.Activity, error) {
		return activityService.activityOperation.GetActivities(firstDay, lastDay)
	})
	if res != nil {
		return res
	}
	return NewApiResponse(SuccessGetActivities, activities)
}

func (activityService *ActivityService) GetActivitiesPage(req *RequestGetActivitiesPage) *ApiResponse[*PageResponse[*operation.Activity]] {
	if req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[*PageResponse[*operation.Activity]](ErrIllegalParam, nil)
	}
	if res := CheckPermission[*PageResponse[*operation.Activity]](req.Permission, operation.ActivityShowList); res != nil {
		return res
	}
	activities, total, err := activityService.activityOperation.GetActivitiesPage(req.Page, req.PageSize)
	if res := CheckDatabaseError[*PageResponse[*operation.Activity]](err); res != nil {
		return res
	}
	return NewApiResponse(SuccessGetActivitiesPage, &PageResponse[*operation.Activity]{
		Items:    activities,
		Page:     req.Page,
		PageSize: req.PageSize,
		Total:    total,
	})
}

func (activityService *ActivityService) GetActivityInfo(req *RequestActivityInfo) *ApiResponse[*operation.Activity] {
	if req.ActivityId <= 0 {
		return NewApiResponse[*operation.Activity](ErrIllegalParam, nil)
	}
	activity, res := CallDBFunc[*operation.Activity, *operation.Activity](func() (*operation.Activity, error) {
		return activityService.activityOperation.GetActivityById(req.ActivityId)
	})
	if res != nil {
		return res
	}
	return NewApiResponse(SuccessGetActivityInfo, activity)
}

func (activityService *ActivityService) AddActivity(req *RequestAddActivity) *ApiResponse[bool] {
	if req.Activity == nil {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ActivityPublish); res != nil {
		return res
	}

	req.Activity.ID = 0
	req.Activity.Publisher = req.Cid

	if res := CallDBFuncWithoutRet[bool](func() error {
		return activityService.activityOperation.SaveActivity(req.Activity)
	}); res != nil {
		return res
	}

	newValue, _ := json.Marshal(req.Activity)
	activityService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: activityService.auditLogOperation.NewAuditLog(
			operation.ActivityCreated,
			req.Cid,
			strconv.Itoa(int(req.Activity.ID)),
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: operation.ValueNotAvailable,
				NewValue: string(newValue),
			}),
	})

	return NewApiResponse(SuccessAddActivity, true)
}

func (activityService *ActivityService) DeleteActivity(req *RequestDeleteActivity) *ApiResponse[bool] {
	if req.ActivityId <= 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ActivityDelete); res != nil {
		return res
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		return activityService.activityOperation.DeleteActivity(req.ActivityId)
	}); res != nil {
		return res
	}

	activityService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: activityService.auditLogOperation.NewAuditLog(
			operation.ActivityDeleted,
			req.Cid,
			strconv.Itoa(int(req.ActivityId)),
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse(SuccessDeleteActivity, true)
}

func (activityService *ActivityService) ControllerJoin(req *RequestControllerJoin) *ApiResponse[bool] {
	if req.ActivityId <= 0 || req.FacilityId <= 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if req.Rating <= fsd.Observer.Index() {
		return NewApiResponse[bool](ErrRatingTooLow, false)
	}

	if res := WithErrorHandlerWithoutRet[bool](func(err error) *ApiResponse[bool] {
		if errors.Is(err, operation.ErrRatingNotAllowed) {
			return NewApiResponse(ErrRatingTooLow, false)
		}
		if errors.Is(err, operation.ErrFacilityAlreadyExists) {
			return NewApiResponse(ErrFacilityAlreadyExist, false)
		}
		if errors.Is(err, operation.ErrFacilitySigned) {
			return NewApiResponse(ErrFacilityAlreadySigned, false)
		}
		return nil
	}).CallDBFuncWithoutRet(func() error {
		activity, err := activityService.activityOperation.GetActivityById(req.ActivityId)
		if err != nil {
			return err
		}
		if activity.Status >= int(operation.InActive) {
			return operation.ErrActivityHasClosed
		}
		user, err := activityService.userOperation.GetUserByUid(req.Uid)
		if err != nil {
			return err
		}
		facility, err := activityService.activityOperation.GetFacilityById(req.FacilityId)
		if err != nil {
			return err
		}
		if facility.ActivityId != req.ActivityId {
			return operation.ErrActivityIdMismatch
		}
		return activityService.activityOperation.SignFacilityController(facility, user)
	}); res != nil {
		return res
	}

	return NewApiResponse(SuccessSignFacility, true)
}

func (activityService *ActivityService) ControllerLeave(req *RequestControllerLeave) *ApiResponse[bool] {
	if req.ActivityId <= 0 || req.FacilityId <= 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := WithErrorHandlerWithoutRet[bool](func(err error) *ApiResponse[bool] {
		if errors.Is(err, operation.ErrFacilityNotSigned) {
			return NewApiResponse(ErrFacilityUnSigned, false)
		}
		if errors.Is(err, operation.ErrFacilityNotYourSign) {
			return NewApiResponse(ErrFacilityNotYourSign, false)
		}
		return nil
	}).CallDBFuncWithoutRet(func() error {
		activity, err := activityService.activityOperation.GetActivityById(req.ActivityId)
		if err != nil {
			return err
		}
		if activity.Status >= int(operation.InActive) {
			return operation.ErrActivityHasClosed
		}
		facility, err := activityService.activityOperation.GetFacilityById(req.FacilityId)
		if err != nil {
			return err
		}
		if facility.ActivityId != req.ActivityId {
			return operation.ErrActivityIdMismatch
		}
		return activityService.activityOperation.UnsignFacilityController(facility, req.Uid)
	}); res != nil {
		return res
	}

	return NewApiResponse(SuccessUnsignFacility, true)
}

func (activityService *ActivityService) PilotJoin(req *RequestPilotJoin) *ApiResponse[bool] {
	if req.ActivityId <= 0 || req.Callsign == "" || req.AircraftType == "" {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := WithErrorHandlerWithoutRet[bool](func(err error) *ApiResponse[bool] {
		if errors.Is(err, operation.ErrActivityAlreadySigned) {
			return NewApiResponse(ErrAlreadySigned, false)
		}
		if errors.Is(err, operation.ErrCallsignAlreadyUsed) {
			return NewApiResponse(ErrCallsignUsed, false)
		}
		return nil
	}).CallDBFuncWithoutRet(func() error {
		activity, err := activityService.activityOperation.GetActivityById(req.ActivityId)
		if err != nil {
			return err
		}
		if activity.Status >= int(operation.InActive) {
			return operation.ErrActivityHasClosed
		}
		return activityService.activityOperation.SignActivityPilot(req.ActivityId, req.Uid, req.Callsign, req.AircraftType)
	}); res != nil {
		return res
	}

	return NewApiResponse(SuccessSignedActivity, true)
}

func (activityService *ActivityService) PilotLeave(req *RequestPilotLeave) *ApiResponse[bool] {
	if req.ActivityId <= 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := WithErrorHandlerWithoutRet[bool](func(err error) *ApiResponse[bool] {
		if errors.Is(err, operation.ErrActivityUnsigned) {
			return NewApiResponse(ErrNoSigned, false)
		}
		return nil
	}).CallDBFuncWithoutRet(func() error {
		activity, err := activityService.activityOperation.GetActivityById(req.ActivityId)
		if err != nil {
			return err
		}
		if activity.Status >= int(operation.InActive) {
			return operation.ErrActivityHasClosed
		}
		return activityService.activityOperation.UnsignActivityPilot(req.ActivityId, req.Uid)
	}); res != nil {
		return res
	}

	return NewApiResponse(SuccessUnsignedActivity, true)
}

func (activityService *ActivityService) EditActivity(req *RequestEditActivity) *ApiResponse[bool] {
	if req.Activity == nil {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ActivityEdit); res != nil {
		return res
	}

	activity, res := CallDBFunc[*operation.Activity, bool](func() (*operation.Activity, error) {
		return activityService.activityOperation.GetActivityById(req.ID)
	})
	if res != nil {
		return res
	}

	oldValue, _ := json.Marshal(activity)

	if req.ImageUrl != "" && req.ImageUrl != activity.ImageUrl && activity.ImageUrl != "" {
		_, err := activityService.storeService.DeleteImageFile(activity.ImageUrl)
		if err != nil {
			activityService.logger.ErrorF("err while delete old activity image, %v", err)
		}
	}

	updateInfo := req.Activity.Diff(activity)

	if res := CallDBFuncWithoutRet[bool](func() error {
		return activityService.activityOperation.UpdateActivityInfo(activity, req.Activity, updateInfo)
	}); res != nil {
		return res
	}

	newValue, _ := json.Marshal(req.Activity)
	activityService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: activityService.auditLogOperation.NewAuditLog(
			operation.ActivityUpdated,
			req.Cid,
			strconv.Itoa(int(req.Activity.ID)),
			req.Ip,
			req.UserAgent, &operation.ChangeDetail{
				OldValue: string(oldValue),
				NewValue: string(newValue),
			},
		),
	})

	return NewApiResponse(SuccessEditActivity, true)
}

func (activityService *ActivityService) EditActivityStatus(req *RequestEditActivityStatus) *ApiResponse[bool] {
	if req.ActivityId <= 0 || req.Status < int(operation.Open) || req.Status > int(operation.Closed) {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ActivityEditState); res != nil {
		return res
	}

	status := operation.ActivityStatus(req.Status)

	if res := CallDBFuncWithoutRet[bool](func() error {
		return activityService.activityOperation.SetActivityStatus(req.ActivityId, status)
	}); res != nil {
		return res
	}

	return NewApiResponse(SuccessEditActivityStatus, true)
}

func (activityService *ActivityService) EditPilotStatus(req *RequestEditPilotStatus) *ApiResponse[bool] {
	if req.ActivityId <= 0 || req.UserId <= 0 || req.Status < int(operation.Signed) || req.Status > int(operation.Landing) {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ActivityEditPilotState); res != nil {
		return res
	}

	status := operation.ActivityPilotStatus(req.Status)

	if res := CallDBFuncWithoutRet[bool](func() error {
		pilot, err := activityService.activityOperation.GetActivityPilotById(req.ActivityId, req.UserId)
		if err != nil {
			return err
		}
		return activityService.activityOperation.SetActivityPilotStatus(pilot, status)
	}); res != nil {
		return res
	}

	return NewApiResponse(SuccessEditPilotsStatus, true)
}
