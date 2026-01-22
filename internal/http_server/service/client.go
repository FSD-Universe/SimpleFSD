// Package service
// 存放 ClientServiceInterface 的实现
package service

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type ClientService struct {
	logger            log.LoggerInterface
	clientManager     fsd.ClientManagerInterface
	messageQueue      queue.MessageQueueInterface
	config            *config.HttpServerConfig
	userOperation     operation.UserOperationInterface
	auditLogOperation operation.AuditLogOperationInterface
	whazzupContent    *utils.CachedValue[[]byte]
}

func NewClientService(
	logger log.LoggerInterface,
	config *config.HttpServerConfig,
	userOperation operation.UserOperationInterface,
	auditLogOperation operation.AuditLogOperationInterface,
	clientManager fsd.ClientManagerInterface,
	messageQueue queue.MessageQueueInterface,
) *ClientService {
	service := &ClientService{
		logger:            log.NewLoggerAdapter(logger, "ClientService"),
		clientManager:     clientManager,
		config:            config,
		userOperation:     userOperation,
		auditLogOperation: auditLogOperation,
		messageQueue:      messageQueue,
	}
	service.whazzupContent = utils.NewCachedValue(clientManager.GetWhazzupCacheTime(), service.getWhazzupContent)
	return service
}

func (clientService *ClientService) getWhazzupContent() []byte {
	data := clientService.clientManager.GetWhazzupContent()
	jsonBlob, err := json.Marshal(data)
	if err != nil {
		clientService.logger.ErrorF("marshal whazzup content failed: %v", err)
		clientService.logger.ErrorF("whazzup content: %#v", data)
		return nil
	}
	return jsonBlob
}

func (clientService *ClientService) GetOnlineClients() []byte {
	return clientService.whazzupContent.GetValue()
}

func (clientService *ClientService) SendMessageToClient(req *RequestSendMessageToClient) *ApiResponse[bool] {
	if req.Uid <= 0 || req.SendTo == "" || req.Message == "" {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ClientSendMessage); res != nil {
		return res
	}

	if err := clientService.messageQueue.SyncPublish(&queue.Message{
		Type: queue.SendMessageToClient,
		Data: &fsd.SendRawMessageData{
			From:    clientService.config.FormatCallsign(req.Cid),
			To:      req.SendTo,
			Message: req.Message,
		},
	}); err != nil {
		if errors.Is(err, fsd.ErrCallsignNotFound) {
			return NewApiResponse(ErrClientNotFound, false)
		}
		return NewApiResponse(ErrSendMessage, false)
	}

	clientService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: clientService.auditLogOperation.NewAuditLog(
			operation.ClientMessage,
			req.Cid,
			fmt.Sprintf("%s(%s)", req.SendTo, req.Message),
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse(SuccessSendMessage, true)
}

func (clientService *ClientService) KillClient(req *RequestKillClient) *ApiResponse[bool] {
	if req.Uid <= 0 || req.TargetCallsign == "" {
		return NewApiResponse(ErrIllegalParam, false)
	}

	user, res := CheckPermissionFromDatabase[bool](clientService.userOperation, req.Uid, operation.ClientKill)
	if res != nil {
		return res
	}

	client, err := clientService.clientManager.KickClientFromServer(req.TargetCallsign, req.Reason)
	if err != nil {
		// KickClientFromServer目前仅返回ErrCallsignNotFound错误
		if errors.Is(err, fsd.ErrCallsignNotFound) {
			return NewApiResponse(ErrClientNotFound, false)
		}
		return NewApiResponse(ErrUnknownServerError, false)
	}

	clientService.messageQueue.Publish(&queue.Message{
		Type: queue.SendKickedFromServerEmail,
		Data: &interfaces.KickedFromServerEmailData{
			User:     client.User(),
			Operator: user,
			Reason:   req.Reason,
		},
	})

	clientService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: clientService.auditLogOperation.NewAuditLog(
			operation.ClientKicked,
			req.Cid,
			fmt.Sprintf("%s(%s)", req.TargetCallsign, req.Reason),
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse(SuccessKillClient, true)
}

func (clientService *ClientService) GetClientFlightPath(req *RequestClientPath) *ApiResponse[[]*fsd.PilotPath] {
	if req.Callsign == "" {
		return NewApiResponse[[]*fsd.PilotPath](ErrIllegalParam, nil)
	}

	client, exist := clientService.clientManager.GetClient(req.Callsign)
	if !exist {
		return NewApiResponse[[]*fsd.PilotPath](ErrClientNotFound, nil)
	}

	return NewApiResponse(SuccessGetClientPath, client.Paths())
}

func (clientService *ClientService) SendBroadcastMessage(req *RequestSendBroadcastMessage) *ApiResponse[bool] {
	if req.Message == "" || !fsd.IsValidBroadcastTarget(req.Target) {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.ClientSendBroadcastMessage); res != nil {
		return res
	}

	clientService.messageQueue.Publish(&queue.Message{
		Type: queue.BroadcastMessage,
		Data: &fsd.BroadcastMessageData{
			From:    clientService.config.FormatCallsign(req.Cid),
			Target:  fsd.BroadcastTarget(req.Target),
			Message: req.Message,
		},
	})

	clientService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: clientService.auditLogOperation.NewAuditLog(
			operation.ClientBroadcastMessage,
			req.Cid,
			req.Target,
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: operation.ValueNotAvailable,
				NewValue: req.Message,
			},
		),
	})

	return NewApiResponse(SuccessSendBroadcastMessage, true)
}
