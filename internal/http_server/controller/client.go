// Package controller
package controller

import (
	"net/http"

	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/labstack/echo/v4"
)

type ClientControllerInterface interface {
	GetOnlineClients(ctx echo.Context) error
	GetClientPath(ctx echo.Context) error
	SendMessageToClient(ctx echo.Context) error
	KillClient(ctx echo.Context) error
	BroadcastMessage(ctx echo.Context) error
}

type ClientController struct {
	logger        log.LoggerInterface
	clientService ClientServiceInterface
}

func NewClientController(logger log.LoggerInterface, clientService ClientServiceInterface) *ClientController {
	return &ClientController{
		logger:        log.NewLoggerAdapter(logger, "ClientController"),
		clientService: clientService,
	}
}

func (controller *ClientController) GetOnlineClients(ctx echo.Context) error {
	data := controller.clientService.GetOnlineClients()
	if data == nil {
		return NewErrorResponse(ctx, ErrMarshalJson)
	}
	return ctx.JSONBlob(http.StatusOK, data)
}

func (controller *ClientController) GetClientPath(ctx echo.Context) error {
	data := &RequestClientPath{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("GetClientFlightPath bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.clientService.GetClientFlightPath(data).Response(ctx)
}

func (controller *ClientController) SendMessageToClient(ctx echo.Context) error {
	data := &RequestSendMessageToClient{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("SendMessageToClient bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	if err := SetJwtInfoAndEchoContent(data, ctx); err != nil {
		controller.logger.ErrorF("SendMessageToClient jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.clientService.SendMessageToClient(data).Response(ctx)
}

func (controller *ClientController) KillClient(ctx echo.Context) error {
	data := &RequestKillClient{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("KillClient bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	if err := SetJwtInfoAndEchoContent(data, ctx); err != nil {
		controller.logger.ErrorF("KillClient jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.clientService.KillClient(data).Response(ctx)
}

func (controller *ClientController) BroadcastMessage(ctx echo.Context) error {
	data := &RequestSendBroadcastMessage{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("BroadcastMessage bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	if err := SetJwtInfoAndEchoContent(data, ctx); err != nil {
		controller.logger.ErrorF("BroadcastMessage jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.clientService.SendBroadcastMessage(data).Response(ctx)
}
