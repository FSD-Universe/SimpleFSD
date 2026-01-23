// Package controller
package controller

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/labstack/echo/v4"
)

type UserControllerInterface interface {
	UserRegister(ctx echo.Context) error
	UserLogin(ctx echo.Context) error
	CheckUserAvailability(ctx echo.Context) error
	GetCurrentUserProfile(ctx echo.Context) error
	EditCurrentProfile(ctx echo.Context) error
	GetUserProfile(ctx echo.Context) error
	EditProfile(ctx echo.Context) error
	GetUsers(ctx echo.Context) error
	EditUserPermission(ctx echo.Context) error
	GetUserHistory(ctx echo.Context) error
	GetToken(ctx echo.Context) error
	ResetUserPassword(ctx echo.Context) error
	UserFsdLogin(ctx echo.Context) error
	UserFsdToken(ctx echo.Context) error
}

type UserController struct {
	logger  log.LoggerInterface
	service UserServiceInterface
}

func NewUserHandler(logger log.LoggerInterface, service UserServiceInterface) *UserController {
	return &UserController{
		logger:  log.NewLoggerAdapter(logger, "UserController"),
		service: service,
	}
}

func (controller *UserController) UserRegister(ctx echo.Context) error {
	data := &RequestUserRegister{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("UserRegister bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.UserRegister(data).Response(ctx)
}

func (controller *UserController) UserLogin(ctx echo.Context) error {
	data := &RequestUserLogin{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("UserLogin bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.UserLogin(data).Response(ctx)
}

func (controller *UserController) CheckUserAvailability(ctx echo.Context) error {
	data := &RequestUserAvailability{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("CheckUserAvailability bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.CheckAvailability(data).Response(ctx)
}

func (controller *UserController) GetCurrentUserProfile(ctx echo.Context) error {
	data := &RequestUserCurrentProfile{}
	if err := SetJwtInfo(data, ctx); err != nil {
		controller.logger.ErrorF("GetCurrentUserProfile jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	res := controller.service.GetCurrentProfile(data)
	if res.HttpCode != http.StatusOK {
		return res.Response(ctx)
	}

	if data.TokenType == MainToken {
		return res.Response(ctx)
	}

	d := &OAuth2User{
		Username: res.Data.Username,
		Email:    res.Data.Email,
		Cid:      res.Data.Cid,
		QQ:       res.Data.QQ,
	}
	return NewApiResponse(res.ApiStatus, d).Response(ctx)
}

func (controller *UserController) EditCurrentProfile(ctx echo.Context) error {
	data := &RequestUserEditCurrentProfile{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("EditCurrentProfile bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	if err := SetJwtInfo(data, ctx); err != nil {
		controller.logger.ErrorF("EditCurrentProfile jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.EditCurrentProfile(data).Response(ctx)
}

func (controller *UserController) GetUserProfile(ctx echo.Context) error {
	data := &RequestUserProfile{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("GetUserProfile bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	if err := SetJwtInfo(data, ctx); err != nil {
		controller.logger.ErrorF("GetUserProfile jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.GetUserProfile(data).Response(ctx)
}

func (controller *UserController) EditProfile(ctx echo.Context) error {
	data := &RequestUserEditProfile{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("EditProfile bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	if err := SetJwtInfoAndEchoContent(data, ctx); err != nil {
		controller.logger.ErrorF("EditProfile jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.EditUserProfile(data).Response(ctx)
}

func (controller *UserController) GetUsers(ctx echo.Context) error {
	data := &RequestUserList{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("GetUsers bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	if err := SetJwtInfo(data, ctx); err != nil {
		controller.logger.ErrorF("GetUsers jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.GetUserList(data).Response(ctx)
}

func (controller *UserController) EditUserPermission(ctx echo.Context) error {
	data := &RequestUserEditPermission{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("EditUserPermission bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	if err := SetJwtInfoAndEchoContent(data, ctx); err != nil {
		controller.logger.ErrorF("EditUserPermission jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.EditUserPermission(data).Response(ctx)
}

func (controller *UserController) GetUserHistory(ctx echo.Context) error {
	data := &RequestGetUserHistory{}
	if err := SetJwtInfo(data, ctx); err != nil {
		controller.logger.ErrorF("GetUserHistory jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.GetUserHistory(data).Response(ctx)
}

func (controller *UserController) GetToken(ctx echo.Context) error {
	data := &RequestGetToken{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("UserController.GetToken bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	token := ctx.Get("user").(*jwt.Token)
	claim := token.Claims.(*Claims)
	data.Claims = claim
	return controller.service.GetTokenWithFlushToken(data).Response(ctx)
}

func (controller *UserController) ResetUserPassword(ctx echo.Context) error {
	data := &RequestResetUserPassword{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("ResetUserPassword bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	SetEchoContent(data, ctx)
	return controller.service.ResetUserPassword(data).Response(ctx)
}

func (controller *UserController) UserFsdLogin(ctx echo.Context) error {
	data := &RequestFsdLogin{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("UserFsdLogin bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return ctx.JSON(http.StatusOK, controller.service.UserFsdLogin(data))
}

func (controller *UserController) UserFsdToken(ctx echo.Context) error {
	data := &RequestFsdToken{}
	if err := SetJwtInfo(data, ctx); err != nil {
		controller.logger.ErrorF("UserFsdToken jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	return controller.service.UserFsdToken(data).Response(ctx)
}
