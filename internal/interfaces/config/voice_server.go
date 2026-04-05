// Package config
package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
)

type TTSEngine string

const (
	TTSEngineAliYun    TTSEngine = "aliyun"
	TTSEnginePocketTTS TTSEngine = "pocket-tts"
)

type TTSServer struct {
	Engine TTSEngine `json:"engine"`
	Url    string    `json:"url"`
	Model  string    `json:"model"`
	Voice  string    `json:"voice"`
	ApiKey string    `json:"api_key"`
}

type ATISConfig struct {
	Enable           bool          `json:"enable"`
	ATISPlayInterval string        `json:"atis_play_interval"`
	ATISPlayDuration time.Duration `json:"-"`
	OPUSSampleRate   int           `json:"opus_sample_rate"`
	OPUSChannel      int           `json:"opus_channel"`
	OPUSFrameTime    int           `json:"opus_frame_time"`
	TTSServer        *TTSServer    `json:"tts"`
}

type VoiceServerConfig struct {
	Enabled           bool          `json:"enabled"`
	TCPHost           string        `json:"tcp_host"`
	TCPPort           uint          `json:"tcp_port"`
	TCPAddress        string        `json:"-"`
	UDPHost           string        `json:"udp_host"`
	UDPPort           uint          `json:"udp_port"`
	UDPAddress        string        `json:"-"`
	TimeoutInterval   string        `json:"timeout_interval"`
	TimeoutDuration   time.Duration `json:"-"`
	MaxDataSize       int           `json:"max_data_size"`
	BroadcastLimit    int           `json:"broadcast_limit"`
	UDPPacketLimit    int           `json:"udp_packet_limit"`
	TCPPacketLimit    int           `json:"tcp_packet_limit"`
	MinimumPilotRange float64       `json:"minimum_pilot_range"`
	ATIS              *ATISConfig   `json:"atis"`
}

func defaultVoiceServerConfig() *VoiceServerConfig {
	return &VoiceServerConfig{
		Enabled:           false,
		TCPHost:           "0.0.0.0",
		TCPPort:           6808,
		UDPHost:           "0.0.0.0",
		UDPPort:           6807,
		TimeoutInterval:   "30s",
		MaxDataSize:       1024 * 1024,
		BroadcastLimit:    128,
		UDPPacketLimit:    8192,
		TCPPacketLimit:    32,
		MinimumPilotRange: 10.0,
		ATIS: &ATISConfig{
			Enable:           false,
			ATISPlayInterval: "5s",
			OPUSSampleRate:   48000,
			OPUSChannel:      1,
			OPUSFrameTime:    20,
			TTSServer: &TTSServer{
				Engine: TTSEngineAliYun,
				Url:    "https://dashscope.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation",
				Model:  "qwen3-tts-instruct-flash",
				Voice:  "Neil",
				ApiKey: "",
			},
		},
	}
}

func (config *VoiceServerConfig) checkValid(_ log.LoggerInterface) *ValidResult {
	if config.Enabled {
		if result := checkPort(config.TCPPort); result.IsFail() {
			return result
		}
		config.TCPAddress = fmt.Sprintf("%s:%d", config.TCPHost, config.TCPPort)

		if result := checkPort(config.UDPPort); result.IsFail() {
			return result
		}
		config.UDPAddress = fmt.Sprintf("%s:%d", config.UDPHost, config.UDPPort)

		if duration, err := time.ParseDuration(config.TimeoutInterval); err != nil {
			return ValidFailWith(errors.New("invalid json field voice_server.ping_interval"), err)
		} else {
			config.TimeoutDuration = duration
		}
		if config.ATIS.Enable {
			if config.ATIS.OPUSSampleRate <= 0 {
				return ValidFail(errors.New("invalid json field voice_server.opus_sample_rate"))
			}
			if config.ATIS.OPUSChannel <= 0 {
				return ValidFail(errors.New("invalid json field voice_server.opus_channel"))
			}
			if config.ATIS.OPUSFrameTime <= 0 {
				return ValidFail(errors.New("invalid json field voice_server.opus_frame_time"))
			}
			if duration, err := time.ParseDuration(config.ATIS.ATISPlayInterval); err != nil {
				return ValidFailWith(errors.New("invalid json field voice_server.atis_play_interval"), err)
			} else {
				config.ATIS.ATISPlayDuration = duration
			}
			if config.ATIS.TTSServer.Engine == TTSEngineAliYun {
				if config.ATIS.TTSServer.Url == "" {
					return ValidFail(errors.New("invalid json field voice_server.tts.url"))
				}
				if config.ATIS.TTSServer.Model == "" {
					return ValidFail(errors.New("invalid json field voice_server.tts.model"))
				}
				if config.ATIS.TTSServer.Voice == "" {
					return ValidFail(errors.New("invalid json field voice_server.tts.model"))
				}
				if config.ATIS.TTSServer.ApiKey == "" {
					return ValidFail(errors.New("invalid json field voice_server.tts.api_key"))
				}
			} else if config.ATIS.TTSServer.Engine == TTSEnginePocketTTS {
				if config.ATIS.TTSServer.Url == "" {
					return ValidFail(errors.New("invalid json field voice_server.tts.url"))
				}
				if config.ATIS.TTSServer.Voice == "" {
					return ValidFail(errors.New("invalid json field voice_server.tts.model"))
				}
			} else {
				return ValidFail(errors.New("invalid json field voice_server.tts.engine, only support aliyun and pocket-tts"))
			}
		}
	}
	return ValidPass()
}
