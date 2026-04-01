// Package config
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
)

type FSDServerConfig struct {
	FSDName              string                  `json:"fsd_name"` // FSD名称
	Host                 string                  `json:"host"`
	Port                 uint                    `json:"port"`
	Address              string                  `json:"-"`
	AirportDataFile      string                  `json:"airport_data_file"`
	AirportData          map[string]*AirportData `json:"-"`
	PosUpdatePoints      int                     `json:"pos_update_points"`
	HeartbeatInterval    string                  `json:"heartbeat_interval"`
	HeartbeatDuration    time.Duration           `json:"-"`
	CacheTime            string                  `json:"whazzup_cache_time"`
	CacheDuration        time.Duration           `json:"-"`
	SessionCleanTime     string                  `json:"session_clean_time"`    // 会话保留时间
	SessionCleanDuration time.Duration           `json:"-"`                     // 内部使用字段
	MaxWorkers           int                     `json:"max_workers"`           // 并发线程数
	MaxBroadcastWorkers  int                     `json:"max_broadcast_workers"` // 广播并发线程数
	MaxConnection        int                     `json:"max_connection"`
	RangeLimit           *FsdRangeLimit          `json:"range_limit"`
	FirstMotdLine        string                  `json:"first_motd_line"`
	Motd                 []string                `json:"motd"`
	CurrentMotd          []string                `json:"-"`
}

func defaultFSDServerConfig() *FSDServerConfig {
	return &FSDServerConfig{
		FSDName:             "Simple-Fsd",
		Host:                "0.0.0.0",
		Port:                6809,
		AirportDataFile:     "data/airport.json",
		PosUpdatePoints:     1,
		CacheTime:           "15s",
		HeartbeatInterval:   "40s",
		SessionCleanTime:    "40s",
		MaxWorkers:          128,
		MaxBroadcastWorkers: 128,
		MaxConnection:       2,
		RangeLimit:          defaultFsdRangeLimitConfig(),
		FirstMotdLine:       "Welcome to use %[1]s v%[2]s",
		Motd:                make([]string, 0),
		CurrentMotd:         make([]string, 0),
	}
}

func (config *FSDServerConfig) checkValid(logger log.LoggerInterface) *ValidResult {
	if config.MaxBroadcastWorkers > runtime.NumCPU()*50 {
		config.MaxBroadcastWorkers = runtime.NumCPU() * 50
	}

	if result := config.RangeLimit.checkValid(logger); result.IsFail() {
		return result
	}

	if result := checkPort(config.Port); result.IsFail() {
		return result
	}

	data := make([]string, 0, 1+len(config.Motd))
	data = append(data, fmt.Sprintf(config.FirstMotdLine, config.FSDName, AppVersion.String()))
	data = append(data, config.Motd...)
	config.CurrentMotd = data

	config.Address = fmt.Sprintf("%s:%d", config.Host, config.Port)

	if config.PosUpdatePoints < 0 {
		return ValidFail(errors.New("invalid json field pos_update_points, pos_update_points must larger than 0"))
	}

	if duration, err := time.ParseDuration(config.CacheTime); err != nil {
		return ValidFailWith(errors.New("invalid json field http_server.email.cache_time"), err)
	} else {
		config.CacheDuration = duration
	}

	fileUrl, _ := url.JoinPath(*global.DownloadPrefix, global.AirportDataFilePath)
	if bytes, err := cachedContent(logger, config.AirportDataFile, fileUrl); err != nil {
		logger.WarnF("fail to load airport data, airport check disable, %v", err)
		config.AirportData = nil
	} else if err := json.Unmarshal(bytes, &config.AirportData); err != nil {
		return ValidFail(fmt.Errorf("invalid json file %s, %v", config.AirportDataFile, err))
	} else {
		logger.InfoF("Airport data loaded, found %d airports", len(config.AirportData))
	}

	if duration, err := time.ParseDuration(config.SessionCleanTime); err != nil {
		return ValidFail(fmt.Errorf("invalid json field session_clean_time, duration parse error, %v", err))
	} else {
		config.SessionCleanDuration = duration
	}

	if duration, err := time.ParseDuration(config.HeartbeatInterval); err != nil {
		return ValidFail(fmt.Errorf("invalid json field heartbead_interval, duration parse error, %v", err))
	} else if duration <= 25*time.Second {
		return ValidFail(fmt.Errorf("heartbead_interval must larger than 25s, got %.0fs", duration.Seconds()))
	} else {
		config.HeartbeatDuration = duration
	}

	return ValidPass()
}
