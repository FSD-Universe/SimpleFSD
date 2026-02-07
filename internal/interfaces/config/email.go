// Package config
package config

import (
	"errors"
	"regexp"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"gopkg.in/gomail.v2"
)

type EmailConfig struct {
	Host                  string                `json:"host"`
	Port                  int                   `json:"port"`
	EmailServer           *gomail.Dialer        `json:"-"`
	Username              string                `json:"username"`
	Password              string                `json:"password"`
	VerifyExpiredTime     string                `json:"verify_expired_time"`
	VerifyExpiredDuration time.Duration         `json:"-"`
	SendInterval          string                `json:"send_interval"`
	SendDuration          time.Duration         `json:"-"`
	AllowedHost           string                `json:"allowed_hosts"`
	AllowedHostPattern    *regexp.Regexp        `json:"-"`
	Template              *EmailTemplateConfigs `json:"template"`
}

func defaultEmailConfig() *EmailConfig {
	return &EmailConfig{
		Host:              "smtp.qq.com",
		Port:              465,
		Username:          "example@qq.com",
		Password:          "123456",
		VerifyExpiredTime: "5m",
		SendInterval:      "1m",
		AllowedHost:       "^.*$",
		Template:          defaultEmailTemplateConfig(),
	}
}

func (config *EmailConfig) checkValid(logger log.LoggerInterface) *ValidResult {
	if duration, err := time.ParseDuration(config.VerifyExpiredTime); err != nil {
		return ValidFailWith(errors.New("invalid json field http_server.email.verify_expired_time"), err)
	} else {
		config.VerifyExpiredDuration = duration
	}

	if duration, err := time.ParseDuration(config.SendInterval); err != nil {
		return ValidFailWith(errors.New("invalid json field http_server.email.send_interval"), err)
	} else {
		config.SendDuration = duration
	}

	if result := config.Template.checkValid(logger); result.IsFail() {
		return result
	}

	if *global.SkipEmailVerification {
		config.EmailServer = nil
	} else {
		config.EmailServer = gomail.NewDialer(config.Host, config.Port, config.Username, config.Password)
		dial, err := config.EmailServer.Dial()
		if err != nil {
			return ValidFailWith(errors.New("connecting to smtp server fail"), err)
		}
		_ = dial.Close()
	}

	config.AllowedHostPattern = regexp.MustCompile(config.AllowedHost)

	return ValidPass()
}
