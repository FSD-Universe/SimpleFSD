// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package tts
package tts

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
)

type PocketTTS struct {
	voiceName  string
	url        string
	httpClient *http.Client
}

func NewPocketTTS(c *config.TTSServer) *PocketTTS {
	return &PocketTTS{
		voiceName: c.Voice,
		url:       c.Url,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (tts *PocketTTS) Synthesize(text string) (audio []byte, err error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("text", text)
	_ = writer.WriteField("voice_url", tts.voiceName)
	_ = writer.Close()

	req, err := http.NewRequest("POST", tts.url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := tts.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer func(Body io.ReadCloser) { _ = Body.Close() }(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server error (status %d)", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
