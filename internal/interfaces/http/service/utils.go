// Package service
package service

import (
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/labstack/echo/v4"
)

type HttpCode int

const (
	Unsatisfied         HttpCode = 0
	Ok                  HttpCode = 200
	NoContent           HttpCode = 204
	Found               HttpCode = 302
	BadRequest          HttpCode = 400
	Unauthorized        HttpCode = 401
	PermissionDenied    HttpCode = 403
	NotFound            HttpCode = 404
	Conflict            HttpCode = 409
	ServerInternalError HttpCode = 500
	NotImplemented      HttpCode = 501
)

func (hc HttpCode) Code() int {
	return int(hc)
}

type ApiStatus struct {
	StatusName  string
	Description string
	HttpCode    HttpCode
}

func NewApiStatus(statusName, description string, httpCode HttpCode) *ApiStatus {
	return &ApiStatus{
		StatusName:  statusName,
		Description: description,
		HttpCode:    httpCode,
	}
}

type ApiResponse[T any] struct {
	HttpCode int    `json:"-"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Data     T      `json:"data"`
}

type TokenType int

const (
	MainToken TokenType = 1 << iota
	MainRefreshToken
	OAuth2Token
)

type Claims struct {
	Uid        uint   `json:"uid"`
	Cid        int    `json:"cid,omitempty"`
	Username   string `json:"username,omitempty"`
	Rating     int    `json:"rating,omitempty"`
	TokenType  int    `json:"token_type"`
	Scopes     string `json:"scopes,omitempty"`
	Permission uint64 `json:"permission,omitempty"`
	config     *config.JWTConfig
	jwt.RegisteredClaims
}

type FsdClaims struct {
	ControllerRating int `json:"controller_rating"`
	PilotRating      int `json:"pilot_rating"`
	config           *config.JWTConfig
	jwt.RegisteredClaims
}

type PageArguments struct {
	Page     int `query:"page_number"`
	PageSize int `query:"page_size"`
}

type PageResponse[T any] struct {
	Items    []T   `json:"items"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Total    int64 `json:"total"`
}

type EchoContentHeader struct {
	Ip        string
	UserAgent string
}

func (content *EchoContentHeader) SetIp(ip string) { content.Ip = ip }

func (content *EchoContentHeader) SetUserAgent(ua string) { content.UserAgent = ua }

type JwtHeader struct {
	Uid        uint
	Permission uint64
	Cid        int
	Rating     int
}

func (jwt *JwtHeader) SetUid(uid uint) { jwt.Uid = uid }

func (jwt *JwtHeader) SetCid(cid int) { jwt.Cid = cid }

func (jwt *JwtHeader) SetPermission(permission uint64) { jwt.Permission = permission }

func (jwt *JwtHeader) SetRating(rating int) { jwt.Rating = rating }

func NewClaims(config *config.JWTConfig, user *operation.User, tokenType TokenType) *Claims {
	var expiredDuration time.Duration
	switch tokenType {
	case MainToken:
		expiredDuration = config.ExpiresDuration
	case MainRefreshToken:
		expiredDuration = config.ExpiresDuration + config.RefreshDuration
	case OAuth2Token:
		return nil
	}
	return &Claims{
		Uid:        user.ID,
		Cid:        user.Cid,
		Username:   user.Username,
		Permission: user.Permission,
		Rating:     user.Rating,
		TokenType:  int(tokenType),
		config:     config,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "FsdHttpServer",
			Subject:   user.Username,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiredDuration)),
		},
	}
}

func NewOAuth2Claims(config *config.HttpServerConfig, userId uint, tokenType TokenType, scopes string) *Claims {
	return &Claims{
		Uid:       userId,
		TokenType: int(tokenType),
		Scopes:    scopes,
		config:    config.JWT,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "FsdHttpServer",
			Subject:   strconv.Itoa(int(userId)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.OAuth2.AccessTokenExpireDuration)),
		},
	}
}

func NewFsdClaims(config *config.JWTConfig, user *operation.User) *FsdClaims {
	return &FsdClaims{
		ControllerRating: user.Rating,
		PilotRating:      0,
		config:           config,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "FsdHttpServer",
			Subject:   user.Username,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.ExpiresDuration)),
		},
	}
}

func (claim *Claims) GenerateToken() string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claim)
	tokenString, _ := token.SignedString([]byte(claim.config.Secret))
	return tokenString
}

func (claim *FsdClaims) GenerateToken() string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claim)
	tokenString, _ := token.SignedString([]byte(claim.config.Secret))
	return tokenString
}

func (res *ApiResponse[T]) Response(ctx echo.Context) error {
	return ctx.JSON(res.HttpCode, res)
}

func TextResponse(ctx echo.Context, httpCode int, content string) error {
	return ctx.String(httpCode, content)
}

var (
	ErrIllegalParam          = NewApiStatus("PARAM_ERROR", "参数不正确", BadRequest)
	ErrParseParam            = NewApiStatus("PARAM_PARSE_ERROR", "参数解析错误", BadRequest)
	ErrNoPermission          = NewApiStatus("NO_PERMISSION", "无权这么做", PermissionDenied)
	ErrDatabaseFail          = NewApiStatus("DATABASE_ERROR", "服务器内部错误", ServerInternalError)
	ErrMissingOrMalformedJwt = NewApiStatus("MISSING_OR_MALFORMED_JWT", "缺少JWT令牌或者令牌格式错误", BadRequest)
	ErrInvalidOrExpiredJwt   = NewApiStatus("INVALID_OR_EXPIRED_JWT", "无效或过期的JWT令牌", Unauthorized)
	ErrInvalidJwtType        = NewApiStatus("INVALID_JWT_TYPE", "非法的JWT令牌类型", Unauthorized)
	ErrUnknownJwtError       = NewApiStatus("UNKNOWN_JWT_ERROR", "未知的JWT解析错误", ServerInternalError)
	ErrUnknownServerError    = NewApiStatus("UNKNOWN_ERROR", "未知服务器错误", ServerInternalError)
	ErrCreateRequest         = NewApiStatus("ERR_CREATE_REQUEST", "创建请求失败", ServerInternalError)
	ErrSendRequest           = NewApiStatus("ERR_SEND_REQUEST", "请求目标失败", ServerInternalError)
	ErrCopyRequest           = NewApiStatus("ERR_COPY_REQUEST", "复制目标请求", ServerInternalError)
	ErrNotAvailable          = NewApiStatus("ERR_NOT_AVAILABLE", "航图服务不可用", ServerInternalError)
	ErrTokenExpired          = NewApiStatus("TOKEN_EXPIRED", "令牌已过期，请联系管理员", Unauthorized)
	ErrInvalidPageParam      = NewApiStatus("INVALID_PAGE_PARAM", "无效的分页参数", BadRequest)
)

func NewErrorResponse(ctx echo.Context, codeStatus *ApiStatus) error {
	return NewApiResponse[any](codeStatus, nil).Response(ctx)
}

func NewJsonResponse(ctx echo.Context, code HttpCode, data any) error {
	return ctx.JSON(code.Code(), data)
}

func NewApiResponse[T any](codeStatus *ApiStatus, data T) *ApiResponse[T] {
	return &ApiResponse[T]{
		HttpCode: codeStatus.HttpCode.Code(),
		Code:     codeStatus.StatusName,
		Message:  codeStatus.Description,
		Data:     data,
	}
}

func CheckDatabaseError[T any](err error) *ApiResponse[T] {
	var zero T
	switch {
	case errors.Is(err, operation.ErrIdentifierCheck):
		return NewApiResponse[T](ErrRegisterFail, zero)
	case errors.Is(err, operation.ErrIdentifierTaken):
		return NewApiResponse[T](ErrIdentifierTaken, zero)
	case errors.Is(err, operation.ErrUserNotFound):
		return NewApiResponse[T](ErrUserNotFound, zero)
	case errors.Is(err, operation.ErrActivityNotFound):
		return NewApiResponse[T](ErrActivityNotFound, zero)
	case errors.Is(err, operation.ErrFlightPlanNotFound):
		return NewApiResponse[T](ErrFlightPlanNotFound, zero)
	case errors.Is(err, operation.ErrTicketNotFound):
		return NewApiResponse[T](ErrTicketNotFound, zero)
	case errors.Is(err, operation.ErrTicketAlreadyClosed):
		return NewApiResponse[T](ErrTicketAlreadyClosed, zero)
	case errors.Is(err, operation.ErrFacilityNotFound):
		return NewApiResponse[T](ErrFacilityNotFound, zero)
	case errors.Is(err, operation.ErrActivityHasClosed):
		return NewApiResponse[T](ErrActivityLocked, zero)
	case errors.Is(err, operation.ErrActivityIdMismatch):
		return NewApiResponse[T](ErrActivityIdMismatch, zero)
	case errors.Is(err, operation.ErrControllerRecordNotFound):
		return NewApiResponse[T](ErrRecordNotFound, zero)
	case errors.Is(err, operation.ErrApplicationNotFound):
		return NewApiResponse[T](ErrApplicationNotFound, zero)
	case errors.Is(err, operation.ErrApplicationAlreadyExists):
		return NewApiResponse[T](ErrApplicationAlreadyExists, zero)
	case errors.Is(err, operation.ErrAnnouncementNotFound):
		return NewApiResponse[T](ErrAnnouncementNotFound, zero)
	case err != nil:
		return NewApiResponse[T](ErrDatabaseFail, zero)
	default:
		return nil
	}
}

func CheckPermission[T any](permission uint64, perm operation.Permission) *ApiResponse[T] {
	var zero T
	if permission <= 0 {
		return NewApiResponse[T](ErrNoPermission, zero)
	}
	userPermission := operation.Permission(permission)
	if !userPermission.HasPermission(perm) {
		return NewApiResponse[T](ErrNoPermission, zero)
	}
	return nil
}

type Errorhandler[T any] func(err error) *ApiResponse[T]

// CallDBFunc 调用数据库操作函数并处理错误
func CallDBFunc[R any, T any](fc func() (R, error)) (result R, response *ApiResponse[T]) {
	result, err := fc()
	response = CheckDatabaseError[T](err)
	return
}

type CallDatabaseFunc[R any, T any] struct {
	errHandler Errorhandler[T]
}

func WithErrorHandler[R any, T any](errHandler Errorhandler[T]) *CallDatabaseFunc[R, T] {
	return &CallDatabaseFunc[R, T]{
		errHandler: errHandler,
	}
}

func (callFunc *CallDatabaseFunc[R, T]) CallDBFunc(fc func() (R, error)) (result R, response *ApiResponse[T]) {
	result, err := fc()
	if err == nil {
		return
	}
	response = callFunc.errHandler(err)
	if response == nil {
		response = CheckDatabaseError[T](err)
	}
	return
}

func CallDBFuncWithoutRet[T any](fc func() error) *ApiResponse[T] {
	err := fc()
	return CheckDatabaseError[T](err)
}

type CallDatabaseFuncWithoutRet[T any] struct {
	errHandler Errorhandler[T]
}

func WithErrorHandlerWithoutRet[T any](errHandler Errorhandler[T]) *CallDatabaseFuncWithoutRet[T] {
	return &CallDatabaseFuncWithoutRet[T]{
		errHandler: errHandler,
	}
}

func (callFunc *CallDatabaseFuncWithoutRet[T]) CallDBFuncWithoutRet(fc func() error) (response *ApiResponse[T]) {
	err := fc()
	if err == nil {
		return
	}
	response = callFunc.errHandler(err)
	if response == nil {
		response = CheckDatabaseError[T](err)
	}
	return
}

func GetTargetUserAndCheckPermissionFromDatabase[T any](
	userOperation operation.UserOperationInterface,
	uid uint,
	targetUid uint,
	perm operation.Permission,
) (user *operation.User, targetUser *operation.User, response *ApiResponse[T]) {
	if user, response = CallDBFunc[*operation.User, T](func() (*operation.User, error) {
		return userOperation.GetUserByUid(uid)
	}); response != nil {
		return
	}
	if response = CheckPermission[T](user.Permission, perm); response != nil {
		return
	}
	targetUser, response = CallDBFunc[*operation.User, T](func() (*operation.User, error) {
		return userOperation.GetUserByUid(targetUid)
	})
	return
}

func CheckPermissionFromDatabase[T any](
	userOperation operation.UserOperationInterface,
	uid uint,
	perm operation.Permission,
) (user *operation.User, response *ApiResponse[T]) {
	if user, response = CallDBFunc[*operation.User, T](func() (*operation.User, error) {
		return userOperation.GetUserByUid(uid)
	}); response != nil {
		return
	}
	response = CheckPermission[T](user.Permission, perm)
	return
}

type VersionInfo struct {
	Version    string `json:"version"`
	GitVersion string `json:"git_version"`
	GitCommit  string `json:"git_commit"`
	BuildTime  string `json:"build_time"`
}
