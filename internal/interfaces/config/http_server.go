// Package config
package config

import (
	"errors"
	"fmt"

	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
)

type HttpServerConfig struct {
	Enabled        bool             `json:"enabled"`
	ServerAddress  string           `json:"server_address"`
	Host           string           `json:"host"`
	Port           uint             `json:"port"`
	Address        string           `json:"-"`
	ClientPrefix   string           `json:"client_prefix"`
	ClientSuffix   string           `json:"client_suffix"`
	ProxyType      int              `json:"proxy_type"`
	TrustedIpRange []string         `json:"trusted_ip_range"`
	BodyLimit      string           `json:"body_limit"`
	Store          *HttpServerStore `json:"store"`
	RateLimit      int              `json:"rateLimit"`
	Email          *EmailConfig     `json:"email"`
	JWT            *JWTConfig       `json:"jwt"`
	SSL            *SSLConfig       `json:"ssl"`
	Navigraph      *NavigraphConfig `json:"navigraph"`
	OAuth2         *OAuth2Config    `json:"oauth2"`
}

func defaultHttpServerConfig() *HttpServerConfig {
	return &HttpServerConfig{
		Enabled:        false,
		Host:           "0.0.0.0",
		Port:           6810,
		ClientPrefix:   "(",
		ClientSuffix:   ")",
		ServerAddress:  "http://127.0.0.1:6810",
		ProxyType:      0,
		TrustedIpRange: make([]string, 0),
		BodyLimit:      "10MB",
		RateLimit:      15,
		Store:          defaultHttpServerStore(),
		Email:          defaultEmailConfig(),
		JWT:            defaultJWTConfig(),
		SSL:            defaultSSLConfig(),
		Navigraph:      defaultNavigraphConfig(),
		OAuth2:         defaultOAuth2Config(),
	}
}

func (config *HttpServerConfig) FormatCallsign(cid int) string {
	return fmt.Sprintf("%s%04d%s", config.ClientPrefix, cid, config.ClientSuffix)
}

func (config *HttpServerConfig) checkValid(logger log.LoggerInterface) *ValidResult {
	if config.Enabled {
		if result := checkPort(config.Port); result.IsFail() {
			return result
		}

		config.Address = fmt.Sprintf("%s:%d", config.Host, config.Port)

		if config.BodyLimit == "" {
			logger.WarnF("body_limit is empty, where the length of the request body is not restricted. This is a very dangerous behavior")
		}

		if config.ClientPrefix == "" && config.ClientSuffix == "" {
			return ValidFail(errors.New("client_prefix and client_suffix can't be empty at the same time"))
		}

		if config.RateLimit < 0 {
			logger.WarnF("Invalid rate limit value %d, using default 15", config.RateLimit)
			config.RateLimit = 15
		}

		if result := config.SSL.checkValid(logger); result.IsFail() {
			return result
		}
		if result := config.Email.checkValid(logger); result.IsFail() {
			return result
		}
		if result := config.JWT.checkValid(logger); result.IsFail() {
			return result
		}
		if result := config.SSL.checkValid(logger); result.IsFail() {
			return result
		}
		if result := config.Store.checkValid(logger); result.IsFail() {
			return result
		}
		if result := config.Navigraph.checkValid(logger); result.IsFail() {
			return result
		}
		if result := config.OAuth2.checkValid(); result.IsFail() {
			return result
		}
	}
	return ValidPass()
}
