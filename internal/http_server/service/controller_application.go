// Package service
package service

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/half-nothing/simple-fsd/internal/interfaces"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type ControllerApplicationService struct {
	logger               log.LoggerInterface
	messageQueue         queue.MessageQueueInterface
	applicationOperation operation.ControllerApplicationOperationInterface
	userOperation        operation.UserOperationInterface
	auditLogOperation    operation.AuditLogOperationInterface
}

func NewControllerApplicationService(
	logger log.LoggerInterface,
	messageQueue queue.MessageQueueInterface,
	applicationOperation operation.ControllerApplicationOperationInterface,
	userOperation operation.UserOperationInterface,
	auditLogOperation operation.AuditLogOperationInterface,
) *ControllerApplicationService {
	return &ControllerApplicationService{
		logger:               logger,
		messageQueue:         messageQueue,
		applicationOperation: applicationOperation,
		userOperation:        userOperation,
		auditLogOperation:    auditLogOperation,
	}
}

func (service *ControllerApplicationService) GetSelfApplication(req *RequestGetSelfApplication) *ApiResponse[ResponseGetSelfApplication] {
	application, res := CallDBFunc[*operation.ControllerApplication, ResponseGetSelfApplication](func() (*operation.ControllerApplication, error) {
		return service.applicationOperation.GetApplicationByUserId(req.Uid)
	})
	if res != nil {
		return res
	}

	return NewApiResponse(SuccessGetSelfApplication, application)
}

func (service *ControllerApplicationService) GetApplications(req *RequestGetApplications) *ApiResponse[ResponseGetApplications] {
	if req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[ResponseGetApplications](ErrIllegalParam, nil)
	}

	if res := CheckPermission[ResponseGetApplications](req.Permission, operation.ControllerApplicationShowList); res != nil {
		return res
	}

	applications, total, err := service.applicationOperation.GetApplications(req.Page, req.PageSize)
	if res := CheckDatabaseError[ResponseGetApplications](err); res != nil {
		return res
	}

	return NewApiResponse(SuccessGetApplications, &PageResponse[*operation.ControllerApplication]{
		Items:    applications,
		Page:     req.Page,
		PageSize: req.PageSize,
		Total:    total,
	})
}

func (service *ControllerApplicationService) SubmitControllerApplication(req *RequestSubmitControllerApplication) *ApiResponse[bool] {
	if req.ControllerApplication == nil || req.WhyWantToBeController == "" || req.ControllerRecord == "" {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if req.IsGuest && (req.Platform == "" || req.Evidence == "") {
		return NewApiResponse(ErrIllegalParam, false)
	}

	req.ControllerApplication.ID = 0
	req.ControllerApplication.UserId = req.Uid
	req.ControllerApplication.Status = int(operation.Submitted)
	req.ControllerApplication.Message = ""

	if res := CallDBFuncWithoutRet[bool](func() error {
		return service.applicationOperation.SaveApplication(req.ControllerApplication)
	}); res != nil {
		return res
	}

	newValue, _ := json.Marshal(req.ControllerApplication)
	service.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: service.auditLogOperation.NewAuditLog(
			operation.ControllerApplicationSubmit,
			req.Cid,
			strconv.Itoa(int(req.ControllerApplication.ID)),
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: operation.ValueNotAvailable,
				NewValue: string(newValue),
			},
		),
	})

	return NewApiResponse(SuccessSubmitApplication, true)
}

func (service *ControllerApplicationService) CancelSelfApplication(req *RequestCancelSelfApplication) *ApiResponse[bool] {
	application, res := CallDBFunc[*operation.ControllerApplication, bool](func() (*operation.ControllerApplication, error) {
		return service.applicationOperation.GetApplicationByUserId(req.Uid)
	})
	if res != nil {
		return res
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		return service.applicationOperation.CancelApplication(application)
	}); res != nil {
		return res
	}

	oldValue, _ := json.Marshal(application)
	service.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: service.auditLogOperation.NewAuditLog(
			operation.ControllerApplicationCancel,
			req.Cid,
			strconv.Itoa(int(application.ID)),
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: string(oldValue),
				NewValue: operation.ValueNotAvailable,
			},
		),
	})

	return NewApiResponse(SuccessCancelApplication, true)
}

func (service *ControllerApplicationService) UpdateApplicationStatus(req *RequestUpdateApplicationStatus) *ApiResponse[bool] {
	if req.ApplicationId <= 0 || !operation.IsValidApplicationStatus(req.Status) {
		return NewApiResponse(ErrIllegalParam, false)
	}

	user, res := CallDBFunc[*operation.User, bool](func() (*operation.User, error) {
		return service.userOperation.GetUserByUid(req.Uid)
	})
	if res != nil {
		return res
	}

	applicationStatus := operation.ControllerApplicationStatus(req.Status)
	var auditEventType operation.AuditEventType
	var object string

	switch applicationStatus {
	case operation.Submitted:
		return NewApiResponse(ErrIllegalParam, false)
	case operation.UnderProcessing:
		if res := CheckPermission[bool](req.Permission, operation.ControllerApplicationConfirm); res != nil {
			return res
		}
		if len(req.AvailableTime) == 0 {
			return NewApiResponse(ErrIllegalParam, false)
		}
		auditEventType = operation.ControllerApplicationProcessing
	case operation.Passed:
		if req.Message == "" {
			return NewApiResponse(ErrIllegalParam, false)
		}
		if res := CheckPermission[bool](req.Permission, operation.ControllerApplicationPass); res != nil {
			return res
		}
		auditEventType = operation.ControllerApplicationPassed
	case operation.Rejected:
		if req.Message == "" {
			return NewApiResponse(ErrIllegalParam, false)
		}
		if res := CheckPermission[bool](req.Permission, operation.ControllerApplicationReject); res != nil {
			return res
		}
		auditEventType = operation.ControllerApplicationRejected
	}

	application, res := CallDBFunc[*operation.ControllerApplication, bool](func() (*operation.ControllerApplication, error) {
		return service.applicationOperation.GetApplicationById(req.ApplicationId)
	})
	if res != nil {
		return res
	}

	if req.Status == application.Status {
		return NewApiResponse(ErrSameApplicationStatus, false)
	}

	if val, ok := operation.AllowedStatusMap[operation.ControllerApplicationStatus(application.Status)]; ok {
		if !slices.Contains(val, applicationStatus) {
			return NewApiResponse(ErrStatusCantFallBack, false)
		}
	}

	var emailType queue.MessageType
	var emailData interface{}

	if applicationStatus == operation.UnderProcessing {
		if res := CallDBFuncWithoutRet[bool](func() error {
			return service.applicationOperation.ConfirmApplicationUnderProcessing(application)
		}); res != nil {
			return res
		}
		emailType = queue.SendApplicationProcessingEmail
		emailData = &interfaces.ApplicationProcessingEmailData{
			User:           application.User,
			Operator:       user,
			AvailableTimes: req.AvailableTime,
		}
		object = fmt.Sprintf("%d(%s)", application.ID, utils.FormatCid(application.User.Cid))
	} else {
		if res := CallDBFuncWithoutRet[bool](func() error {
			return service.applicationOperation.UpdateApplicationStatus(application, applicationStatus, req.Message)
		}); res != nil {
			return res
		}

		object = fmt.Sprintf("%d(%s): %s", application.ID, utils.FormatCid(application.User.Cid), req.Message)

		if applicationStatus == operation.Passed {
			emailType = queue.SendApplicationPassedEmail
			emailData = &interfaces.ApplicationPassedEmailData{
				User:     application.User,
				Operator: user,
				Message:  req.Message,
			}
		} else {
			emailType = queue.SendApplicationRejectedEmail
			emailData = &interfaces.ApplicationRejectedEmailData{
				User:     application.User,
				Operator: user,
				Reason:   req.Message,
			}
		}
	}

	service.messageQueue.Publish(&queue.Message{
		Type: emailType,
		Data: emailData,
	})

	service.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: service.auditLogOperation.NewAuditLog(
			auditEventType,
			req.Cid,
			object,
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse(SuccessUpdateApplication, true)
}
