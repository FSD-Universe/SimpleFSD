// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package config
package config

import (
	"errors"

	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
)

type CORSConfig struct {
	AllowOrigins     []string `json:"allow_origins"`
	AllowMethods     []string `json:"allow_methods"`
	AllowHeaders     []string `json:"allow_headers"`
	ExposeHeaders    []string `json:"expose_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           int      `json:"max_age"`
}

func defaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{},
		AllowCredentials: false,
		MaxAge:           86400,
	}
}

func (c *CORSConfig) checkValid(_ log.LoggerInterface) *ValidResult {
	if c.MaxAge < 0 {
		return ValidFailWith(errors.New("max_age must be greater than 0"), nil)
	}

	if len(c.AllowOrigins) == 0 {
		return ValidFailWith(errors.New("allow_origins must be not empty"), nil)
	}

	if len(c.AllowOrigins) == 1 && c.AllowOrigins[0] == "*" && c.AllowCredentials {
		return ValidFailWith(errors.New("allow_credentials cannot be true when allow_origins is *"), nil)
	}

	if len(c.AllowMethods) == 0 {
		return ValidFailWith(errors.New("allow_methods must be not empty"), nil)
	}

	return ValidPass()
}
