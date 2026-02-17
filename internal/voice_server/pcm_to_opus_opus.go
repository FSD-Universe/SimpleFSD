// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

//go:build opus

package voice_server

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/hraban/opus"
)

type OpusEncoder struct {
	encoderPool sync.Pool
	voiceConfig *config.VoiceServerConfig
	frameSize   int
}

func NewOpusEncoder(voiceConfig *config.VoiceServerConfig) *OpusEncoder {
	encoder := &OpusEncoder{
		voiceConfig: voiceConfig,
		frameSize:   voiceConfig.OPUSSampleRate * voiceConfig.OPUSFrameTime / 1000,
	}
	encoder.encoderPool = sync.Pool{
		New: func() interface{} {
			enc, err := opus.NewEncoder(voiceConfig.OPUSSampleRate, voiceConfig.OPUSChannel, opus.AppVoIP)
			if err != nil {
				return nil
			}
			return enc
		},
	}
	return encoder
}

func (encoder *OpusEncoder) resample(pcm []byte) []byte {
	if len(pcm) == 0 {
		return nil
	}
	if len(pcm)%2 != 0 {
		return nil
	}
	out := make([]byte, 0, len(pcm)*2)
	for i := 0; i < len(pcm); i += 2 {
		out = append(out, pcm[i], pcm[i+1])
		out = append(out, pcm[i], pcm[i+1])
	}
	return out
}

// EncodePCM 一次性将整段 PCM 转为多帧 Opus，返回每帧一个 []byte，便于按帧广播。
func (encoder *OpusEncoder) EncodePCM(pcm []byte) (opusFrames [][]byte, err error) {
	if len(pcm) == 0 {
		return nil, nil
	}
	pcm48k := encoder.resample(pcm)
	if pcm48k == nil {
		return nil, fmt.Errorf("audio: resample 24k to 48k failed")
	}
	samples := len(pcm48k) / 2
	pcm16 := make([]int16, samples)
	for i := 0; i < samples; i++ {
		pcm16[i] = int16(binary.LittleEndian.Uint16(pcm48k[i*2 : i*2+2]))
	}
	raw := encoder.encoderPool.Get()
	var enc *opus.Encoder
	if raw != nil {
		enc = raw.(*opus.Encoder)
	}
	if enc == nil {
		enc, err = opus.NewEncoder(encoder.voiceConfig.OPUSSampleRate, encoder.voiceConfig.OPUSChannel, opus.AppVoIP)
		if err != nil {
			return nil, fmt.Errorf("audio: new opus encoder: %w", err)
		}
	}
	defer func() {
		if enc != nil {
			encoder.encoderPool.Put(enc)
		}
	}()

	buf := make([]byte, 4096)
	var frames [][]byte
	for i := 0; i+encoder.frameSize <= len(pcm16); i += encoder.frameSize {
		frame := pcm16[i : i+encoder.frameSize]
		n, err := enc.Encode(frame, buf)
		if err != nil {
			return nil, fmt.Errorf("audio: opus encode frame: %w", err)
		}
		frames = append(frames, append([]byte(nil), buf[:n]...))
	}
	return frames, nil
}
