// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

//go:build !opus

package voice_server

import (
	"errors"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
)

type OpusEncoder struct {
	voiceConfig *config.VoiceServerConfig
}

func NewOpusEncoder(voiceConfig *config.VoiceServerConfig) *OpusEncoder {
	return &OpusEncoder{voiceConfig: voiceConfig}
}

// EncodePCM 存根：未使用 -tags opus 编译时，ATIS 语音编码不可用。
func (encoder *OpusEncoder) EncodePCM(pcm []byte) (opusFrames [][]byte, err error) {
	return nil, errors.New("opus not available: build with -tags opus and libopus installed")
}
