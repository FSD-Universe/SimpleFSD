// Package service
package service

import (
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/labstack/echo/v4"
)

var (
	ErrUserNotFound            = NewApiStatus("USER_NOT_FOUND", "指定用户不存在", NotFound)
	ErrRegisterFail            = NewApiStatus("REGISTER_FAIL", "注册失败", ServerInternalError)
	ErrIdentifierTaken         = NewApiStatus("USER_EXISTS", "用户已存在", BadRequest)
	ErrCidNotMatch             = NewApiStatus("CID_NOT_MATCH", "注册cid与验证码发送时的cid不一致", BadRequest)
	ErrEmailExpired            = NewApiStatus("EMAIL_CODE_EXPIRED", "验证码已过期", BadRequest)
	ErrEmailIllegal            = NewApiStatus("EMAIL_CODE_ILLEGAL", "非法验证码", BadRequest)
	ErrEmailCodeInvalid        = NewApiStatus("EMAIL_CODE_INVALID", "邮箱验证码错误", BadRequest)
	ErrAccountSuspended        = NewApiStatus("ACCOUNT_SUSPENDED", "您已被封禁", PermissionDenied)
	ErrWrongUsernameOrPassword = NewApiStatus("WRONG_USERNAME_OR_PASSWORD", "用户名或密码错误", NotFound)
	ErrPermissionNodeNotExists = NewApiStatus("PERMISSION_NODE_NOT_EXISTS", "无效权限节点", BadRequest)
	ErrOriginPasswordRequired  = NewApiStatus("ORIGIN_PASSWORD_REQUIRED", "未提供原始密码", BadRequest)
	ErrNewPasswordRequired     = NewApiStatus("NEW_PASSWORD_REQUIRED", "未提供新密码", BadRequest)
	ErrWrongOriginPassword     = NewApiStatus("WRONG_ORIGIN_PASSWORD_ERROR", "原始密码不正确", BadRequest)
	ErrQQInvalid               = NewApiStatus("QQ_INVALID", "qq号不正确", BadRequest)
	ErrResetPasswordFail       = NewApiStatus("RESET_PASSWORD_FAIL", "重置密码失败", ServerInternalError)
	NameNotAvailability        = NewApiStatus("INFO_NOT_AVAILABILITY", "用户信息不可用", Ok)
	NameAvailability           = NewApiStatus("INFO_AVAILABILITY", "用户信息可用", Ok)
	SuccessRegister            = NewApiStatus("REGISTER_SUCCESS", "注册成功", Ok)
	SuccessLogin               = NewApiStatus("LOGIN_SUCCESS", "登陆成功", Ok)
	SuccessGetCurrentProfile   = NewApiStatus("GET_CURRENT_PROFILE_SUCCESS", "获取当前用户信息成功", Ok)
	SuccessEditCurrentProfile  = NewApiStatus("SUCCESS_EDIT_CURRENT_PROFILE", "编辑用户信息成功", Ok)
	SuccessGetProfile          = NewApiStatus("GET_PROFILE_SUCCESS", "获取用户信息成功", Ok)
	SuccessEditUserProfile     = NewApiStatus("EDIT_USER_PROFILE", "修改用户信息成功", Ok)
	SuccessGetUsers            = NewApiStatus("GET_USER_PAGE", "获取用户信息分页成功", Ok)
	SuccessEditUserPermission  = NewApiStatus("EDIT_USER_PERMISSION", "编辑用户权限成功", Ok)
	SuccessGetUserHistory      = NewApiStatus("GET_USER_HISTORY", "成功获取用户历史数据", Ok)
	SuccessGetToken            = NewApiStatus("GET_TOKEN", "成功刷新秘钥", Ok)
	SuccessResetPassword       = NewApiStatus("RESET_PASSWORD", "成功重置密码", Ok)
)

type UserServiceInterface interface {
	UserRegister(req *RequestUserRegister) *ApiResponse[bool]
	UserLogin(req *RequestUserLogin) *ApiResponse[*ResponseUserLogin]
	CheckAvailability(req *RequestUserAvailability) *ApiResponse[bool]
	GetCurrentProfile(req *RequestUserCurrentProfile) *ApiResponse[ResponseUserCurrentProfile]
	EditCurrentProfile(req *RequestUserEditCurrentProfile) *ApiResponse[bool]
	GetUserProfile(req *RequestUserProfile) *ApiResponse[ResponseUserProfile]
	EditUserProfile(req *RequestUserEditProfile) *ApiResponse[bool]
	GetUserList(req *RequestUserList) *ApiResponse[ResponseUserList]
	EditUserPermission(req *RequestUserEditPermission) *ApiResponse[bool]
	GetUserHistory(req *RequestGetUserHistory) *ApiResponse[*ResponseGetUserHistory]
	GetTokenWithFlushToken(req *RequestGetToken) *ApiResponse[*ResponseGetToken]
	ResetUserPassword(req *RequestResetUserPassword) *ApiResponse[bool]
	UserFsdLogin(req *RequestFsdLogin) *ResponseFsdLogin
	UserFsdToken(req *RequestFsdToken) *ApiResponse[ResponseFsdToken]
}

type RequestUserRegister struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Cid       int    `json:"cid"`
	EmailCode string `json:"email_code"`
}

type RequestUserLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ResponseUserLogin struct {
	User       *operation.User `json:"user"`
	Token      string          `json:"token"`
	FlushToken string          `json:"flush_token"`
}

type RequestUserAvailability struct {
	Username string `query:"username"`
	Email    string `query:"email"`
	Cid      string `query:"cid"`
}

type RequestUserCurrentProfile struct {
	JwtHeader
}

type OAuth2User struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Cid       int    `json:"cid"`
	QQ        int    `json:"qq"`
	AvatarUrl string `json:"avatar_url"`
}

type ResponseUserCurrentProfile = *operation.User

type RequestUserEditCurrentProfile struct {
	JwtHeader
	ID             uint   `json:"id"`
	Cid            int    `json:"cid"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	EmailCode      string `json:"email_code"`
	AvatarUrl      string `json:"avatar_url"`
	QQ             int    `json:"qq"`
	OriginPassword string `json:"origin_password"`
	NewPassword    string `json:"new_password"`
}

type RequestUserProfile struct {
	JwtHeader
	TargetUid uint `param:"uid"`
}

type ResponseUserProfile = *operation.User

type RequestUserList struct {
	JwtHeader
	PageArguments
}

type ResponseUserList = *PageResponse[*operation.User]

type RequestUserEditProfile struct {
	JwtHeader
	EchoContentHeader
	TargetUid uint `param:"uid"`
	RequestUserEditCurrentProfile
}

type RequestUserEditPermission struct {
	JwtHeader
	EchoContentHeader
	TargetUid   uint     `param:"uid"`
	Permissions echo.Map `json:"permissions"`
}

type RequestGetUserHistory struct {
	JwtHeader
}

type ResponseGetUserHistory struct {
	*operation.UserHistory
	TotalAtcTime   int `json:"total_atc_time"`
	TotalPilotTime int `json:"total_pilot_time"`
}

type RequestGetToken struct {
	*Claims
	FirstTime bool `query:"first"`
}

type ResponseGetToken struct {
	User       *operation.User `json:"user"`
	Token      string          `json:"token"`
	FlushToken string          `json:"flush_token"`
}

type RequestResetUserPassword struct {
	EchoContentHeader
	Email     string `json:"email"`
	EmailCode string `json:"email_code"`
	Password  string `json:"password"`
}

type RequestFsdLogin struct {
	Cid        string `json:"cid"`
	Password   string `json:"password"`
	IsSweatbox bool   `json:"is_sweatbox"`
}

type ResponseFsdLogin struct {
	Success bool   `json:"success"`
	ErrMsg  string `json:"error_msg"`
	Token   string `json:"token"`
}

type RequestFsdToken struct {
	JwtHeader
}

type ResponseFsdToken = string
