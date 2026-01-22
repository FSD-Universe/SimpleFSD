// Package service
// 存放 UserServiceInterface 的实现
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type UserService struct {
	logger            log.LoggerInterface
	config            *config.HttpServerConfig
	messageQueue      queue.MessageQueueInterface
	emailService      EmailServiceInterface
	userOperation     operation.UserOperationInterface
	historyOperation  operation.HistoryOperationInterface
	storeService      StoreServiceInterface
	auditLogOperation operation.AuditLogOperationInterface
}

func NewUserService(
	logger log.LoggerInterface,
	config *config.HttpServerConfig,
	messageQueue queue.MessageQueueInterface,
	userOperation operation.UserOperationInterface,
	historyOperation operation.HistoryOperationInterface,
	auditLogOperation operation.AuditLogOperationInterface,
	storeService StoreServiceInterface,
	emailService EmailServiceInterface,
) *UserService {
	return &UserService{
		logger:            log.NewLoggerAdapter(logger, "UserService"),
		messageQueue:      messageQueue,
		emailService:      emailService,
		config:            config,
		userOperation:     userOperation,
		historyOperation:  historyOperation,
		storeService:      storeService,
		auditLogOperation: auditLogOperation,
	}
}

func (userService *UserService) verifyEmailCode(email string, emailCode string, cid int) *ApiStatus {
	err := userService.emailService.VerifyEmailCode(email, emailCode, cid)
	switch {
	case errors.Is(err, ErrEmailCodeExpired):
		return ErrEmailExpired
	case errors.Is(err, ErrEmailCodeIllegal):
		return ErrEmailIllegal
	case errors.Is(err, ErrInvalidEmailCode):
		return ErrEmailCodeInvalid
	case errors.Is(err, ErrCidMismatch):
		return ErrCidNotMatch
	default:
		return nil
	}
}

func (userService *UserService) UserRegister(req *RequestUserRegister) *ApiResponse[bool] {
	if req.Username == "" || req.Email == "" || req.Password == "" || req.Cid <= 0 || len(req.EmailCode) != 6 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := userService.verifyEmailCode(req.Email, req.EmailCode, req.Cid); res != nil {
		return NewApiResponse(res, false)
	}

	user, err := userService.userOperation.NewUser(req.Username, req.Email, req.Cid, req.Password)
	if res := CheckDatabaseError[bool](err); res != nil {
		return res
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		return userService.userOperation.AddUser(user)
	}); res != nil {
		return res
	}

	userService.messageQueue.Publish(&queue.Message{
		Type: queue.DeleteVerifyCode,
		Data: req.Email,
	})

	return NewApiResponse(SuccessRegister, true)
}

func (userService *UserService) UserLogin(req *RequestUserLogin) *ApiResponse[*ResponseUserLogin] {
	if req.Username == "" || req.Password == "" {
		return NewApiResponse[*ResponseUserLogin](ErrIllegalParam, nil)
	}

	userId := operation.GetUserId(req.Username)

	user, res := CallDBFunc[*operation.User, *ResponseUserLogin](func() (*operation.User, error) {
		return userId.GetUser(userService.userOperation)
	})
	if res != nil {
		return res
	}

	if user.Rating <= fsd.Ban.Index() {
		return NewApiResponse[*ResponseUserLogin](ErrAccountSuspended, nil)
	}

	if pass := userService.userOperation.VerifyUserPassword(user, req.Password); !pass {
		return NewApiResponse[*ResponseUserLogin](ErrWrongUsernameOrPassword, nil)
	}

	token := NewClaims(userService.config.JWT, user, MainToken)
	flushToken := NewClaims(userService.config.JWT, user, MainRefreshToken)
	return NewApiResponse(SuccessLogin, &ResponseUserLogin{
		User:       user,
		Token:      token.GenerateToken(),
		FlushToken: flushToken.GenerateToken(),
	})
}

func (userService *UserService) CheckAvailability(req *RequestUserAvailability) *ApiResponse[bool] {
	if req.Username == "" && req.Email == "" && req.Cid == "" {
		return NewApiResponse(ErrIllegalParam, false)
	}

	exist, err := userService.userOperation.IsUserIdentifierTaken(nil, utils.StrToInt(req.Cid, 0), req.Username, req.Email)
	if res := CheckDatabaseError[bool](err); res != nil {
		return res
	}

	return NewApiResponse(NameAvailability, exist)
}

func (userService *UserService) GetCurrentProfile(req *RequestUserCurrentProfile) *ApiResponse[ResponseUserCurrentProfile] {
	if req.TokenType == OAuth2Token && !strings.Contains(req.Scopes, string(config.ScopeProfile)) {
		return NewApiResponse[ResponseUserCurrentProfile](ErrNoPermission, nil)
	}

	user, res := CallDBFunc[*operation.User, ResponseUserCurrentProfile](func() (*operation.User, error) {
		return userService.userOperation.GetUserByUid(req.Uid)
	})
	if res != nil {
		return res
	}

	if user.Rating <= fsd.Ban.Index() {
		return NewApiResponse[ResponseUserCurrentProfile](ErrAccountSuspended, nil)
	}

	if req.TokenType == MainToken {
		return NewApiResponse(SuccessGetCurrentProfile, user)
	}

	data := &operation.User{
		Username: user.Username,
		Email:    user.Email,
		Cid:      user.Cid,
		QQ:       user.QQ,
	}

	return NewApiResponse(SuccessGetCurrentProfile, data)
}

func checkQQ(qq int) *ApiStatus {
	// QQ 号码应当在 10000 - 100000000000之间
	if 1e4 <= qq && qq < 1e11 {
		return nil
	}
	return ErrQQInvalid
}

func (userService *UserService) editUserProfile(req *RequestUserEditCurrentProfile, skipEmailVerify bool, skipPasswordVerify bool) (*ApiStatus, *operation.User, string) {
	if req.Username == "" && req.Email == "" && req.QQ <= 0 && req.OriginPassword == "" && req.NewPassword == "" && req.AvatarUrl == "" {
		return ErrIllegalParam, nil, ""
	}

	if req.OriginPassword != "" && req.NewPassword == "" {
		return ErrNewPasswordRequired, nil, ""
	} else if req.OriginPassword == "" && req.NewPassword != "" && !skipPasswordVerify {
		return ErrOriginPasswordRequired, nil, ""
	}

	if req.Email != "" && !skipEmailVerify {
		if len(req.EmailCode) != 6 {
			return ErrIllegalParam, nil, ""
		}
		if res := userService.verifyEmailCode(req.Email, req.EmailCode, req.Cid); res != nil {
			return res, nil, ""
		}
	}

	if req.QQ > 0 {
		if err := checkQQ(req.QQ); err != nil {
			return err, nil, ""
		}
	}

	user, err := userService.userOperation.GetUserByUid(req.ID)
	if errors.Is(err, operation.ErrUserNotFound) {
		return ErrUserNotFound, nil, ""
	} else if err != nil {
		return ErrDatabaseFail, nil, ""
	}

	updateInfo := &operation.User{}

	oldValue, _ := json.Marshal(user)

	if req.Username != "" || req.Email != "" {
		exist, _ := userService.userOperation.IsUserIdentifierTaken(nil, 0, req.Username, req.Email)
		if exist {
			return ErrIdentifierTaken, nil, ""
		}

		if req.Username != "" && req.Username != user.Username {
			user.Username = req.Username
			updateInfo.Username = req.Username
		}

		if req.Email != "" && req.Email != user.Email {
			user.Email = req.Email
			updateInfo.Email = req.Email
		}
	}

	if req.QQ > 0 && req.QQ != user.QQ {
		user.QQ = req.QQ
		updateInfo.QQ = req.QQ
		if req.AvatarUrl == "" && (user.AvatarUrl == "" || strings.HasPrefix(user.AvatarUrl, "https://q2.qlogo.cn/")) {
			user.AvatarUrl = fmt.Sprintf("https://q2.qlogo.cn/headimg_dl?dst_uin=%d&spec=100", user.QQ)
			updateInfo.AvatarUrl = user.AvatarUrl
		}
	}

	if req.AvatarUrl != "" {
		if user.AvatarUrl != "" && !strings.HasPrefix(user.AvatarUrl, "https://q2.qlogo.cn/") {
			_, err = userService.storeService.DeleteImageFile(user.AvatarUrl)
			if err != nil {
				userService.logger.ErrorF("err while delete user old avatar, %v", err)
			}
		}
		user.AvatarUrl = req.AvatarUrl
		updateInfo.AvatarUrl = user.AvatarUrl
	}

	if req.OriginPassword != "" || (skipPasswordVerify && req.NewPassword != "") {
		password, err := userService.userOperation.UpdateUserPassword(user, req.OriginPassword, req.NewPassword, skipPasswordVerify)
		if errors.Is(err, operation.ErrPasswordEncode) {
			return ErrUnknownServerError, nil, ""
		} else if errors.Is(err, operation.ErrOldPassword) {
			return ErrWrongOriginPassword, nil, ""
		} else if err != nil {
			return ErrDatabaseFail, nil, ""
		}
		updateInfo.Password = string(password)
	}

	if err := userService.userOperation.UpdateUserInfo(user, updateInfo); err != nil {
		if errors.Is(err, operation.ErrUserNotFound) {
			return ErrUserNotFound, nil, ""
		}
		return ErrDatabaseFail, nil, ""
	}

	return nil, user, string(oldValue)
}

func (userService *UserService) EditCurrentProfile(req *RequestUserEditCurrentProfile) *ApiResponse[bool] {
	req.ID = req.JwtHeader.Uid
	req.Cid = req.JwtHeader.Cid
	err, _, _ := userService.editUserProfile(req, false, false)
	if err != nil {
		return NewApiResponse(err, false)
	}
	userService.messageQueue.Publish(&queue.Message{
		Type: queue.DeleteVerifyCode,
		Data: req.Email,
	})
	return NewApiResponse(SuccessEditCurrentProfile, true)
}

func (userService *UserService) GetUserProfile(req *RequestUserProfile) *ApiResponse[ResponseUserProfile] {
	if req.TargetUid <= 0 {
		return NewApiResponse[ResponseUserProfile](ErrIllegalParam, nil)
	}

	if res := CheckPermission[ResponseUserProfile](req.Permission, operation.UserGetProfile); res != nil {
		return res
	}

	user, res := CallDBFunc[*operation.User, ResponseUserProfile](func() (*operation.User, error) {
		return userService.userOperation.GetUserByUid(req.TargetUid)
	})
	if res != nil {
		return res
	}

	return NewApiResponse(SuccessGetProfile, user)
}

func (userService *UserService) EditUserProfile(req *RequestUserEditProfile) *ApiResponse[bool] {
	if req.TargetUid <= 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if res := CheckPermission[bool](req.Permission, operation.UserEditBaseInfo); res != nil {
		return res
	}

	permission := operation.Permission(req.Permission)

	if req.NewPassword != "" && !permission.HasPermission(operation.UserSetPassword) {
		return NewApiResponse(ErrNoPermission, false)
	}

	req.RequestUserEditCurrentProfile.ID = req.TargetUid
	err, user, oldValue := userService.editUserProfile(&req.RequestUserEditCurrentProfile, true, true)
	if err != nil {
		return NewApiResponse(err, false)
	}

	userService.messageQueue.Publish(&queue.Message{
		Type: queue.DeleteVerifyCode,
		Data: req.Email,
	})

	newValue, _ := json.Marshal(user)
	object := fmt.Sprintf("%04d", user.Cid)
	if req.NewPassword != "" {
		object += fmt.Sprintf("(%s)", req.NewPassword)
	}
	userService.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: userService.auditLogOperation.NewAuditLog(
			operation.UserInformationEdit,
			req.JwtHeader.Cid,
			object,
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: oldValue,
				NewValue: string(newValue),
			},
		),
	})

	return NewApiResponse(SuccessEditUserProfile, true)
}

func (userService *UserService) GetUserList(req *RequestUserList) *ApiResponse[ResponseUserList] {
	if req.Page <= 0 || req.PageSize <= 0 {
		return NewApiResponse[ResponseUserList](ErrIllegalParam, nil)
	}

	if res := CheckPermission[ResponseUserList](req.Permission, operation.UserShowList); res != nil {
		return res
	}

	users, total, err := userService.userOperation.GetUsers(req.Page, req.PageSize)
	if res := CheckDatabaseError[ResponseUserList](err); res != nil {
		return res
	}

	return NewApiResponse(SuccessGetUsers, &PageResponse[*operation.User]{
		Items:    users,
		Page:     req.Page,
		PageSize: req.PageSize,
		Total:    total,
	})
}

func (userService *UserService) EditUserPermission(req *RequestUserEditPermission) *ApiResponse[bool] {
	if req.TargetUid <= 0 || len(req.Permissions) == 0 {
		return NewApiResponse(ErrIllegalParam, false)
	}

	user, targetUser, res := GetTargetUserAndCheckPermissionFromDatabase[bool](
		userService.userOperation,
		req.Uid,
		req.TargetUid,
		operation.UserEditPermission,
	)
	if res != nil {
		return res
	}

	permission := operation.Permission(user.Permission)
	targetPermission := operation.Permission(targetUser.Permission)
	permissions := make([]string, 0, len(req.Permissions))
	revokePermissions := make([]string, 0, len(req.Permissions))
	grantPermissions := make([]string, 0, len(req.Permissions))

	for key, value := range req.Permissions {
		if per, ok := operation.PermissionMap[key]; ok {
			if !permission.HasPermission(per) {
				return NewApiResponse(ErrNoPermission, false)
			}
			if value, ok := value.(bool); ok {
				if value {
					targetPermission.Grant(per)
					grantPermissions = append(grantPermissions, key)
				} else {
					targetPermission.Revoke(per)
					revokePermissions = append(revokePermissions, key)
				}
				permissions = append(permissions, key)
			} else {
				return NewApiResponse(ErrIllegalParam, false)
			}
		} else {
			return NewApiResponse(ErrPermissionNodeNotExists, false)
		}
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		return userService.userOperation.UpdateUserPermission(targetUser, targetPermission)
	}); res != nil {
		return res
	}

	userService.messageQueue.Publish(&queue.Message{
		Type: queue.SendPermissionChangeEmail,
		Data: &interfaces.PermissionChangeEmailData{
			User:        targetUser,
			Operator:    user,
			Permissions: permissions,
		},
	})

	if len(grantPermissions) > 0 {
		userService.messageQueue.Publish(&queue.Message{
			Type: queue.AuditLog,
			Data: userService.auditLogOperation.NewAuditLog(
				operation.UserPermissionGrant,
				req.JwtHeader.Cid,
				fmt.Sprintf("%04d", targetUser.Cid),
				req.Ip,
				req.UserAgent,
				&operation.ChangeDetail{
					NewValue: strings.Join(grantPermissions, ","),
				},
			),
		})
	}

	if len(revokePermissions) > 0 {
		userService.messageQueue.Publish(&queue.Message{
			Type: queue.AuditLog,
			Data: userService.auditLogOperation.NewAuditLog(
				operation.UserPermissionRevoke,
				req.JwtHeader.Cid,
				fmt.Sprintf("%04d", targetUser.Cid),
				req.Ip,
				req.UserAgent,
				&operation.ChangeDetail{
					OldValue: strings.Join(revokePermissions, ","),
				},
			),
		})
	}

	return NewApiResponse(SuccessEditUserPermission, true)
}

func (userService *UserService) GetUserHistory(req *RequestGetUserHistory) *ApiResponse[*ResponseGetUserHistory] {
	user, res := CallDBFunc[*operation.User, *ResponseGetUserHistory](func() (*operation.User, error) {
		return userService.userOperation.GetUserByCid(req.Cid)
	})
	if res != nil {
		return res
	}

	userHistory, res := CallDBFunc[*operation.UserHistory, *ResponseGetUserHistory](func() (*operation.UserHistory, error) {
		return userService.historyOperation.GetUserHistory(req.Cid)
	})
	if res != nil {
		return res
	}

	return NewApiResponse(SuccessGetUserHistory, &ResponseGetUserHistory{
		TotalPilotTime: user.TotalPilotTime,
		TotalAtcTime:   user.TotalAtcTime,
		UserHistory:    userHistory,
	})
}

func (userService *UserService) GetTokenWithFlushToken(req *RequestGetToken) *ApiResponse[*ResponseGetToken] {
	user, res := CallDBFunc[*operation.User, *ResponseGetToken](func() (*operation.User, error) {
		return userService.userOperation.GetUserByUid(req.Uid)
	})
	if res != nil {
		return res
	}

	var flushToken string
	if !req.FirstTime && req.ExpiresAt.Add(-2*userService.config.JWT.ExpiresDuration).After(time.Now()) {
		flushToken = ""
	} else {
		flushToken = NewClaims(userService.config.JWT, user, MainRefreshToken).GenerateToken()
	}

	token := NewClaims(userService.config.JWT, user, MainToken)
	return NewApiResponse(SuccessGetToken, &ResponseGetToken{
		User:       user,
		Token:      token.GenerateToken(),
		FlushToken: flushToken,
	})
}

func (userService *UserService) ResetUserPassword(req *RequestResetUserPassword) *ApiResponse[bool] {
	if req.Email == "" || len(req.EmailCode) != 6 || req.Password == "" {
		return NewApiResponse(ErrIllegalParam, false)
	}

	if val := userService.verifyEmailCode(req.Email, req.EmailCode, -1); val != nil {
		return NewApiResponse(val, false)
	}

	targetUser, res := CallDBFunc[*operation.User, bool](func() (*operation.User, error) {
		return userService.userOperation.GetUserByEmail(req.Email)
	})
	if res != nil {
		return res
	}

	password, err := userService.userOperation.UpdateUserPassword(targetUser, "", req.Password, true)
	if err != nil {
		return NewApiResponse(ErrResetPasswordFail, false)
	}

	if res := CallDBFuncWithoutRet[bool](func() error {
		return userService.userOperation.UpdateUserInfo(targetUser, &operation.User{Password: string(password)})
	}); res != nil {
		return res
	}

	userService.messageQueue.Publish(&queue.Message{
		Type: queue.DeleteVerifyCode,
		Data: req.Email,
	})

	userService.messageQueue.Publish(&queue.Message{
		Type: queue.SendPasswordResetEmail,
		Data: &interfaces.PasswordResetEmailData{
			User:      targetUser,
			Ip:        req.Ip,
			UserAgent: req.UserAgent,
		},
	})

	return NewApiResponse(SuccessResetPassword, true)
}

func (userService *UserService) UserFsdLogin(req *RequestFsdLogin) *ResponseFsdLogin {
	if req.Cid == "" || req.Password == "" {
		return &ResponseFsdLogin{Success: false, ErrMsg: "Cid and password properties are both required"}
	}

	userId := operation.GetUserId(req.Cid)

	user, res := CallDBFunc[*operation.User, ResponseFsdLogin](func() (*operation.User, error) {
		return userId.GetUser(userService.userOperation)
	})
	if res != nil {
		return &ResponseFsdLogin{Success: false, ErrMsg: "User not found"}
	}

	if pass := userService.userOperation.VerifyUserPassword(user, req.Password); !pass {
		return &ResponseFsdLogin{Success: false, ErrMsg: "Password is Incorrect"}
	}

	return &ResponseFsdLogin{Success: true, Token: NewFsdClaims(userService.config.JWT, user).GenerateToken()}
}

var (
	SuccessGetFsdToken = NewApiStatus("GET_FSD_TOKEN", "成功获取密钥", Ok)
)

func (userService *UserService) UserFsdToken(req *RequestFsdToken) *ApiResponse[ResponseFsdToken] {
	user, res := CallDBFunc[*operation.User, ResponseFsdToken](func() (*operation.User, error) {
		return userService.userOperation.GetUserByUid(req.Uid)
	})
	if res != nil {
		return NewApiResponse[ResponseFsdToken](ErrUserNotFound, "")
	}

	token := NewFsdClaims(userService.config.JWT, user).GenerateToken()
	return NewApiResponse(SuccessGetFsdToken, token)
}
