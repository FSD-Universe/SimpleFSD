package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/utils"
	"gorm.io/gorm"
)

type OAuth2Service struct {
	logger            log.LoggerInterface
	config            *config.HttpServerConfig
	oauth2Config      *config.OAuth2Config
	messageQueue      queue.MessageQueueInterface
	oauth2Operation   operation.OAuth2OperationInterface
	userOperation     operation.UserOperationInterface
	auditLogOperation operation.AuditLogOperationInterface
}

func NewOAuth2Service(
	lg log.LoggerInterface,
	config *config.HttpServerConfig,
	messageQueue queue.MessageQueueInterface,
	oauth2Operation operation.OAuth2OperationInterface,
	userOperation operation.UserOperationInterface,
	auditLogOperation operation.AuditLogOperationInterface,
) *OAuth2Service {
	return &OAuth2Service{
		logger:            log.NewLoggerAdapter(lg, "OAuth2Service"),
		config:            config,
		oauth2Config:      config.OAuth2,
		messageQueue:      messageQueue,
		oauth2Operation:   oauth2Operation,
		userOperation:     userOperation,
		auditLogOperation: auditLogOperation,
	}
}

func (s *OAuth2Service) generateCode(length int) string {
	seed := []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return base64.URLEncoding.EncodeToString(seed)[:length]
	}
	seed = append(seed, b...)
	return base64.URLEncoding.EncodeToString(seed)[:length]
}

var SuccessCreateClient = NewApiStatus("SUCCESS_CREATE_CLIENT", "客户端创建成功", Ok)

func (s *OAuth2Service) CreateClient(req *CreateClientRequest) *ApiResponse[*ClientInfo] {
	if res := CheckPermission[*ClientInfo](req.Permission, operation.OAuthClientCreate); res != nil {
		return res
	}

	client := &operation.OAuth2Client{
		ClientID:     s.generateCode(32),
		ClientSecret: s.generateCode(64),
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		Enabled:      true,
	}

	if err := s.oauth2Operation.CreateClient(client); err != nil {
		s.logger.ErrorF("Failed to create client: %v", err)
		return NewApiResponse[*ClientInfo](ErrUnknownServerError, nil)
	}

	s.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: s.auditLogOperation.NewAuditLog(
			operation.OAuth2ClientCreated,
			req.Cid,
			client.ClientID,
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse[*ClientInfo](SuccessCreateClient, &ClientInfo{
		ID:           client.ID,
		ClientID:     client.ClientID,
		Name:         client.Name,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
		Enabled:      client.Enabled,
	})
}

var SuccessGetClients = NewApiStatus("SUCCESS_GET_CLIENTS", "客户端列表获取成功", Ok)

func (s *OAuth2Service) GetClients(req *GetClientsPageRequest) *ApiResponse[*PageResponse[*ClientInfo]] {
	if res := CheckPermission[*PageResponse[*ClientInfo]](req.Permission, operation.OAuthClientShowList); res != nil {
		return res
	}

	clients, total, err := s.oauth2Operation.GetClientPage(req.Page, req.PageSize)
	if err != nil {
		s.logger.ErrorF("Failed to get clients: %v", err)
		return NewApiResponse[*PageResponse[*ClientInfo]](ErrUnknownServerError, nil)
	}

	clientInfos := make([]*ClientInfo, 0, len(clients))
	for _, client := range clients {
		clientInfos = append(clientInfos, &ClientInfo{
			ID:           client.ID,
			ClientID:     client.ClientID,
			Name:         client.Name,
			RedirectURIs: client.RedirectURIs,
			Scopes:       client.Scopes,
			Enabled:      client.Enabled,
		})
	}

	return NewApiResponse[*PageResponse[*ClientInfo]](SuccessGetClients, &PageResponse[*ClientInfo]{
		Items:    clientInfos,
		Page:     req.Page,
		PageSize: req.PageSize,
		Total:    total,
	})
}

var SuccessUpdateClient = NewApiStatus("SUCCESS_UPDATE_CLIENT", "客户端更新成功", Ok)

func (s *OAuth2Service) UpdateClient(req *UpdateClientRequest) *ApiResponse[*ClientInfo] {
	if res := CheckPermission[*ClientInfo](req.Permission, operation.OAuthClientEdit); res != nil {
		return res
	}

	client, err := s.oauth2Operation.GetByID(req.ClientID)
	if err != nil {
		s.logger.ErrorF("Failed to get client: %v", err)
		return NewApiResponse[*ClientInfo](ErrUnknownServerError, nil)
	}

	oldVal, _ := json.Marshal(client)

	updates := make(map[string]interface{})

	if req.Name != "" && client.Name != req.Name {
		updates["name"] = req.Name
		client.Name = req.Name
	}

	if len(req.RedirectURIs) > 0 {
		updates["redirect_uris"] = req.RedirectURIs
		client.RedirectURIs = req.RedirectURIs
	}

	if len(req.Scopes) > 0 {
		updates["scopes"] = req.Scopes
		client.Scopes = req.Scopes
	}

	if req.Enabled != nil && client.Enabled != *req.Enabled {
		updates["enabled"] = *req.Enabled
		client.Enabled = *req.Enabled
	}

	if len(updates) == 0 {
		return NewApiResponse[*ClientInfo](ErrIllegalParam, nil)
	}

	if err := s.oauth2Operation.UpdateClient(req.ClientID, updates); err != nil {
		s.logger.ErrorF("Failed to update client: %v", err)
		return NewApiResponse[*ClientInfo](ErrUnknownServerError, nil)
	}

	newVal, _ := json.Marshal(client)

	s.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: s.auditLogOperation.NewAuditLog(
			operation.OAuth2ClientUpdated,
			req.Cid,
			client.ClientID,
			req.Ip,
			req.UserAgent,
			&operation.ChangeDetail{
				OldValue: string(oldVal),
				NewValue: string(newVal),
			},
		),
	})

	return NewApiResponse[*ClientInfo](SuccessUpdateClient, &ClientInfo{
		ID:           client.ID,
		ClientID:     client.ClientID,
		Name:         client.Name,
		RedirectURIs: client.RedirectURIs,
		Scopes:       client.Scopes,
		Enabled:      client.Enabled,
	})
}

var SuccessDeleteClient = NewApiStatus("SUCCESS_DELETE_CLIENT", "客户端删除成功", Ok)

func (s *OAuth2Service) DeleteClient(req *DeleteClientRequest) *ApiResponse[bool] {
	if res := CheckPermission[bool](req.Permission, operation.OAuthClientDelete); res != nil {
		return res
	}

	if err := s.oauth2Operation.DeleteClient(req.ClientID); err != nil {
		s.logger.ErrorF("Failed to delete client: %v", err)
		return NewApiResponse[bool](ErrUnknownServerError, false)
	}

	return NewApiResponse[bool](SuccessDeleteClient, true)
}

func (s *OAuth2Service) Authorize(req *AuthorizeRequest) (*OAuth2ErrorResponse, *operation.OAuth2AuthorizationCode) {
	client, err := s.oauth2Operation.GetByClientID(req.ClientID)
	if err != nil {
		return &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidClient.ErrorCode,
			ErrorDescription: OAuth2ErrUnauthorizedClient.ErrorDescription,
		}, nil
	}

	if !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		return &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrRedirectUriNotAllowed.ErrorCode,
			ErrorDescription: OAuth2ErrRedirectUriNotAllowed.ErrorDescription,
		}, nil
	}

	if req.ResponseType != "code" {
		return &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrUnsupportedResponseType.ErrorCode,
			ErrorDescription: fmt.Sprintf("Unsupported response_type: %s, supported response_type: code", req.ResponseType),
		}, nil
	}

	if s.oauth2Config.RequirePKCE && req.CodeChallengeMethod != string(utils.S256) {
		return &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrUnsupportedChallengeMethod.ErrorCode,
			ErrorDescription: fmt.Sprintf("Unsupported code_challenge_method: %s, supported code_challenge_method: %s", req.CodeChallengeMethod, string(utils.S256)),
		}, nil
	}

	requestedScopes := s.parseScopes(req.Scope)
	if len(requestedScopes) == 0 {
		requestedScopes = s.oauth2Config.DefaultScopes
	}

	scopes := make(map[string]bool)
	for _, scope := range client.Scopes {
		scopes[scope] = true
	}

	for _, scope := range requestedScopes {
		if !scopes[scope] {
			return &OAuth2ErrorResponse{
				ErrorCode:        OAuth2ErrInvalidScope.ErrorCode,
				ErrorDescription: fmt.Sprintf("Scope %s is not allowed", scope),
			}, nil
		}
	}

	authCode := &operation.OAuth2AuthorizationCode{
		ClientID:    req.ClientID,
		Code:        s.generateCode(32),
		State:       req.State,
		Scopes:      req.Scope,
		ExpiresAt:   time.Now().Add(s.oauth2Config.AuthCodeExpireDuration),
		RedirectURI: req.RedirectURI,
		Challenge:   req.CodeChallenge,
	}

	s.logger.InfoF("generated auth code(%s) for client[%s](%s)", authCode.Code, client.Name, client.ClientID)

	if err := s.oauth2Operation.CreateAuthorizationCode(authCode); err != nil {
		s.logger.ErrorF("Failed to create authorization code: %v", err)
		return &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrServerError.ErrorCode,
			ErrorDescription: OAuth2ErrServerError.ErrorDescription,
		}, nil
	}

	return nil, authCode
}

func (s *OAuth2Service) Authorization(req *AuthorizationRequest) (*OAuth2ErrorResponse, string, *operation.OAuth2AuthorizationCode) {
	code, err := s.oauth2Operation.GetAuthorizationCodeById(req.ID)
	if err != nil {
		s.logger.ErrorF("Failed to get authorization code: %v", err)
		return &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrServerError.ErrorCode,
			ErrorDescription: OAuth2ErrServerError.ErrorDescription,
		}, "", nil
	}

	if code.Approved != nil {
		return &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidRequest.ErrorCode,
			ErrorDescription: fmt.Sprintf("Authorization code has already been set"),
		}, code.RedirectURI, nil
	}

	if err := s.oauth2Operation.UpdateAuthorizationCodeById(code.ID, map[string]interface{}{
		"user_id":  req.Uid,
		"approved": req.Approved,
	}); err != nil {
		s.logger.ErrorF("Failed to update authorization code: %v", err)
		return &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrServerError.ErrorCode,
			ErrorDescription: OAuth2ErrServerError.ErrorDescription,
		}, code.RedirectURI, nil
	}

	return nil, code.RedirectURI, code
}

func (s *OAuth2Service) authorizationCode(req *TokenRequest) (*TokenResponse, *OAuth2ErrorResponse) {
	authCode, err := s.oauth2Operation.GetAuthorizationCode(req.Code)
	if err != nil {
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrCodeExpired.ErrorCode,
			ErrorDescription: OAuth2ErrCodeExpired.ErrorDescription,
		}
	}

	if authCode.ClientID != req.ClientID {
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrClientIdMismatch.ErrorCode,
			ErrorDescription: OAuth2ErrClientIdMismatch.ErrorDescription,
		}
	}

	if authCode.Approved == nil {
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrWaitForApproval.ErrorCode,
			ErrorDescription: OAuth2ErrWaitForApproval.ErrorDescription,
		}
	}

	if !*authCode.Approved {
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrAccessDenied.ErrorCode,
			ErrorDescription: OAuth2ErrAccessDenied.ErrorDescription,
		}
	}

	client, err := s.oauth2Operation.GetByClientID(req.ClientID)
	if err != nil {
		s.logger.ErrorF("Failed to get client: %v", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &OAuth2ErrorResponse{
				ErrorCode:        OAuth2ErrInvalidClient.ErrorCode,
				ErrorDescription: OAuth2ErrInvalidClient.ErrorDescription,
			}
		}
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrServerError.ErrorCode,
			ErrorDescription: OAuth2ErrServerError.ErrorDescription,
		}
	}

	if client.ClientSecret != req.ClientSecret {
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrClientSecretMismatch.ErrorCode,
			ErrorDescription: OAuth2ErrClientSecretMismatch.ErrorDescription,
		}
	}

	if s.oauth2Config.RequirePKCE {
		pcke := utils.NewPKCEWithVerifier(req.CodeVerifier)
		if err := pcke.VerifyChallenge(authCode.Challenge); err != nil {
			return nil, &OAuth2ErrorResponse{
				ErrorCode:        OAuth2ErrPKCECodeVerifierFailed.ErrorCode,
				ErrorDescription: OAuth2ErrPKCECodeVerifierFailed.ErrorDescription,
			}
		}
	}

	user, err := s.userOperation.GetUserByUid(authCode.UserID)
	if err != nil {
		s.logger.ErrorF("Failed to get user: %v", err)
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrServerError.ErrorCode,
			ErrorDescription: OAuth2ErrServerError.ErrorDescription,
		}
	}

	accessToken := NewOAuth2Claims(s.config, user.ID, OAuth2Token, authCode.Scopes).GenerateToken()
	refreshToken := s.generateCode(32)

	token := &operation.OAuth2Token{
		ClientID:     req.ClientID,
		UserID:       authCode.UserID,
		TokenType:    "Bearer",
		Scopes:       authCode.Scopes,
		ExpiresAt:    time.Now().Add(s.oauth2Config.RefreshTokenExpireDuration),
		RefreshToken: refreshToken,
	}

	if err := s.oauth2Operation.CreateToken(token); err != nil {
		s.logger.ErrorF("Failed to create token: %v", err)
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrServerError.ErrorCode,
			ErrorDescription: OAuth2ErrServerError.ErrorDescription,
		}
	}

	_ = s.oauth2Operation.DeleteAuthorizationCode(req.Code)

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int64(s.oauth2Config.AccessTokenExpireDuration.Seconds()),
		RefreshToken: refreshToken,
		Scope:        authCode.Scopes,
	}, nil
}

func (s *OAuth2Service) refreshToken(req *TokenRequest) (*TokenResponse, *OAuth2ErrorResponse) {
	token, err := s.oauth2Operation.GetToken(req.RefreshToken)
	if err != nil {
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrRefreshTokenExpired.ErrorCode,
			ErrorDescription: OAuth2ErrRefreshTokenExpired.ErrorDescription,
		}
	}

	if token.ClientID != req.ClientID {
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrClientIdMismatch.ErrorCode,
			ErrorDescription: OAuth2ErrClientIdMismatch.ErrorDescription,
		}
	}

	if token.Client.ClientSecret != req.ClientSecret {
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrClientSecretMismatch.ErrorCode,
			ErrorDescription: OAuth2ErrClientSecretMismatch.ErrorDescription,
		}
	}

	accessToken := NewOAuth2Claims(s.config, token.UserID, OAuth2Token, token.Scopes).GenerateToken()

	_ = s.oauth2Operation.UpdateTokenExpiresAt(req.RefreshToken, time.Now().Add(s.oauth2Config.RefreshTokenExpireDuration))

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   token.TokenType,
		ExpiresIn:   int64(s.oauth2Config.AccessTokenExpireDuration.Seconds()),
		Scope:       token.Scopes,
	}, nil
}

func (s *OAuth2Service) Token(req *TokenRequest) (*TokenResponse, *OAuth2ErrorResponse) {
	switch req.GrantType {
	case "authorization_code":
		return s.authorizationCode(req)
	case "refresh_token":
		return s.refreshToken(req)
	default:
		return nil, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrUnsupportedGrantType.ErrorCode,
			ErrorDescription: fmt.Sprintf("unsupported grant type: %s, supported grant types: authorization_code, refresh_token", req.GrantType),
		}
	}
}

func (s *OAuth2Service) Revoke(req *RevokeRequest) *OAuth2ErrorResponse {
	err := s.oauth2Operation.DeleteToken(req.ClientId, req.Uid, req.Token)
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}

	return &OAuth2ErrorResponse{
		ErrorCode:        OAuth2ErrServerError.ErrorCode,
		ErrorDescription: OAuth2ErrServerError.ErrorDescription,
	}
}

func (s *OAuth2Service) parseScopes(scopeStr string) []string {
	if scopeStr == "" {
		return nil
	}
	scopes := make([]string, 0)
	parts := strings.Split(scopeStr, " ")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	return scopes
}
