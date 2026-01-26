// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package service
package service

import (
	"net/url"

	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
)

type OAuth2ServiceInterface interface {
	CreateClient(req *CreateClientRequest) *ApiResponse[*ClientInfo]
	GetClients(req *GetClientsPageRequest) *ApiResponse[*PageResponse[*ClientInfo]]
	UpdateClient(req *UpdateClientRequest) *ApiResponse[*ClientInfo]
	DeleteClient(req *DeleteClientRequest) *ApiResponse[bool]
	Authorize(req *AuthorizeRequest) (*OAuth2ErrorResponse, *operation.OAuth2AuthorizationCode)
	Authorization(req *AuthorizationRequest) (*OAuth2ErrorResponse, string, *operation.OAuth2AuthorizationCode)
	Token(req *TokenRequest) (*TokenResponse, *OAuth2ErrorResponse)
	Revoke(req *RevokeRequest) *OAuth2ErrorResponse
}

type OAuth2Error struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// OAuth2错误码
var (
	OAuth2ErrInvalidRequest          = &OAuth2Error{ErrorCode: "invalid_request", ErrorDescription: "Invalid request"}
	OAuth2ErrUnauthorizedClient      = &OAuth2Error{ErrorCode: "unauthorized_client", ErrorDescription: "Unauthorized client"}
	OAuth2ErrAccessDenied            = &OAuth2Error{ErrorCode: "access_denied", ErrorDescription: "Access denied"}
	OAuth2ErrUnsupportedResponseType = &OAuth2Error{ErrorCode: "unsupported_response_type", ErrorDescription: "Unsupported response type"}
	OAuth2ErrInvalidScope            = &OAuth2Error{ErrorCode: "invalid_scope", ErrorDescription: "Invalid scope"}
	OAuth2ErrServerError             = &OAuth2Error{ErrorCode: "server_error", ErrorDescription: "Server error"}
	OAuth2ErrTemporarilyUnavailable  = &OAuth2Error{ErrorCode: "temporarily_unavailable", ErrorDescription: "Temporarily unavailable"}

	OAuth2ErrInvalidClient              = &OAuth2Error{ErrorCode: "invalid_client", ErrorDescription: "Invalid or disabled client"}
	OAuth2ErrRedirectUriNotAllowed      = &OAuth2Error{ErrorCode: "redirect_uri_not_allowed", ErrorDescription: "Redirect URI provided was not allowed"}
	OAuth2ErrUnsupportedChallengeMethod = &OAuth2Error{ErrorCode: "unsupported_challenge_method", ErrorDescription: "Unsupported challenge method"}
	OAuth2ErrUnsupportedGrantType       = &OAuth2Error{ErrorCode: "unsupported_grant_type", ErrorDescription: "Unsupported grant type"}
	OAuth2ErrRefreshTokenExpired        = &OAuth2Error{ErrorCode: "refresh_token_expired", ErrorDescription: "Refresh token expired"}
	OAuth2ErrClientIdMismatch           = &OAuth2Error{ErrorCode: "client_id_mismatch", ErrorDescription: "Client ID mismatch"}
	OAuth2ErrClientSecretMismatch       = &OAuth2Error{ErrorCode: "client_secret_mismatch", ErrorDescription: "Client secret mismatch"}
	OAuth2ErrCodeExpired                = &OAuth2Error{ErrorCode: "code_expired", ErrorDescription: "Authorization code expired"}
	OAuth2ErrWaitForApproval            = &OAuth2Error{ErrorCode: "wait_for_approval", ErrorDescription: "Wait for user to approve your request"}
	OAuth2ErrPKCECodeVerifierFailed     = &OAuth2Error{ErrorCode: "pkce_code_verifier_failed", ErrorDescription: "PKCE code verifier failed"}
)

type OAuth2ErrorResponse struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorUri         string `json:"error_uri,omitempty"`
}

func (e *OAuth2ErrorResponse) Error() string {
	return e.ErrorCode
}

func (e *OAuth2ErrorResponse) BuildErrorURL(redirectUri string) string {
	uri, _ := url.Parse(redirectUri)
	query := uri.Query()
	query.Set("error", e.ErrorCode)
	if e.ErrorDescription != "" {
		query.Set("error_description", e.ErrorDescription)
	}
	if e.ErrorUri != "" {
		query.Set("error_uri", e.ErrorUri)
	}
	uri.RawQuery = query.Encode()
	return uri.String()
}

type ClientInfo struct {
	ID           uint     `json:"id"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Enabled      bool     `json:"enabled"`
}

type CreateClientRequest struct {
	JwtHeader
	EchoContentHeader
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
}

type GetClientsPageRequest struct {
	JwtHeader
	PageArguments
}

type UpdateClientRequest struct {
	JwtHeader
	EchoContentHeader
	ClientID     int      `param:"client_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Enabled      *bool    `json:"enabled"`
}

type DeleteClientRequest struct {
	JwtHeader
	EchoContentHeader
	ClientID int `param:"client_id"`
}

type AuthorizeRequest struct {
	ClientID            string `query:"client_id"`
	RedirectURI         string `query:"redirect_uri"`
	ResponseType        string `query:"response_type"`
	Scope               string `query:"scope"`
	State               string `query:"state"`
	CodeChallenge       string `query:"code_challenge"`
	CodeChallengeMethod string `query:"code_challenge_method"`
}

type AuthorizationRequest struct {
	JwtHeader
	ID       uint  `param:"id"`
	Approved *bool `query:"approved" form:"approved" json:"approved"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

type RevokeRequest struct {
	JwtHeader
	ClientId string `json:"client_id" form:"client_id"`
	Token    string `json:"token" form:"token"`
}
