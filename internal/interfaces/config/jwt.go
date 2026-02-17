// Package config
package config

import (
	"errors"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/thanhpk/randstr"
)

type JWTConfig struct {
	Secret             string        `json:"secret"`
	ExpiresTime        string        `json:"expires_time"`
	ExpiresDuration    time.Duration `json:"-"`
	FSDExpiresTime     string        `json:"fsd_expires_time"`
	FSDExpiresDuration time.Duration `json:"-"`
	RefreshTime        string        `json:"refresh_time"`
	RefreshDuration    time.Duration `json:"-"`
}

func defaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		Secret:         randstr.String(64),
		ExpiresTime:    "15m",
		FSDExpiresTime: "4h",
		RefreshTime:    "24h",
	}
}

func (config *JWTConfig) checkValid(logger log.LoggerInterface) *ValidResult {
	if duration, err := time.ParseDuration(config.ExpiresTime); err != nil {
		return ValidFailWith(errors.New("invalid json field http_server.email.jwt_expires_time"), err)
	} else {
		config.ExpiresDuration = duration
	}

	if duration, err := time.ParseDuration(config.RefreshTime); err != nil {
		return ValidFailWith(errors.New("invalid json field http_server.email.jwt_refresh_time"), err)
	} else {
		config.RefreshDuration = duration
	}

	if duration, err := time.ParseDuration(config.FSDExpiresTime); err != nil {
		return ValidFailWith(errors.New("invalid json field http_server.email.jwt_refresh_time"), err)
	} else {
		config.FSDExpiresDuration = duration
	}

	if config.Secret == "" {
		config.Secret = randstr.String(64)
		logger.DebugF("Generate random JWT Secret: %s", config.Secret)
	}

	return ValidPass()
}
