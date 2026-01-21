package config

import (
	"errors"
	"time"
)

type Scope string

const (
	ScopeProfile Scope = "profile"
)

// OAuth2Config OAuth2配置
type OAuth2Config struct {
	Enabled              bool     `json:"enabled"`                // 是否启用OAuth2
	AuthCodeExpire       string   `json:"auth_code_expire"`       // 授权码有效期
	AccessTokenExpire    string   `json:"access_token_expire"`    // 访问令牌有效期
	RefreshTokenExpire   string   `json:"refresh_token_expire"`   // 刷新令牌有效期
	RequirePKCE          bool     `json:"require_pkce"`           // 是否强制要求PKCE
	DefaultScopes        []string `json:"default_scopes"`         // 默认授权范围
	AuthorizationPageURL string   `json:"authorization_page_url"` // 授权页面URL

	AuthCodeExpireDuration     time.Duration `json:"-"`
	AccessTokenExpireDuration  time.Duration `json:"-"`
	RefreshTokenExpireDuration time.Duration `json:"-"`
}

func defaultOAuth2Config() *OAuth2Config {
	return &OAuth2Config{
		Enabled:            false,
		AuthCodeExpire:     "10m",
		AccessTokenExpire:  "1h",
		RefreshTokenExpire: "720h",
		RequirePKCE:        true,
		DefaultScopes:      []string{string(ScopeProfile)},
	}
}

func (config *OAuth2Config) checkValid() *ValidResult {
	if !config.Enabled {
		return ValidPass()
	}

	if config.AuthCodeExpire == "" {
		return ValidFail(errors.New("auth_code_expire cannot be empty"))
	}

	if err := parseDuration(config.AuthCodeExpire, &config.AuthCodeExpireDuration); err != nil {
		return ValidFail(errors.New("auth_code_expire is invalid: " + err.Error()))
	}

	if config.AccessTokenExpire == "" {
		return ValidFail(errors.New("access_token_expire cannot be empty"))
	}

	if err := parseDuration(config.AccessTokenExpire, &config.AccessTokenExpireDuration); err != nil {
		return ValidFail(errors.New("access_token_expire is invalid: " + err.Error()))
	}

	if config.RefreshTokenExpire == "" {
		return ValidFail(errors.New("refresh_token_expire cannot be empty"))
	}

	if err := parseDuration(config.RefreshTokenExpire, &config.RefreshTokenExpireDuration); err != nil {
		return ValidFail(errors.New("refresh_token_expire is invalid: " + err.Error()))
	}

	if len(config.DefaultScopes) == 0 {
		return ValidFail(errors.New("default_scopes cannot be empty"))
	}

	return ValidPass()
}
