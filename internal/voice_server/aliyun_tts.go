// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package voice_server
package voice_server

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"

	"github.com/half-nothing/simple-fsd/internal/utils"
)

const (
	aliyunModelName      = "qwen3-tts-instruct-flash"
	aliyunModelMaxLength = 512
	aliyunVoiceName      = "Neil"
	aliyunLanguageType   = "English"
	aliyunEndpoint       = "https://dashscope.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation"
	aliyunContentType    = "application/json"
)

type AliYunRequestInput struct {
	Text         string `json:"text"`
	Voice        string `json:"voice"`
	LanguageType string `json:"language_type"`
}

type AliYunRequest struct {
	Model string             `json:"model"`
	Input AliYunRequestInput `json:"input"`
}

type AliYunTTS struct {
	apiKey     string
	httpClient *http.Client
}

type AliYunResponse struct {
	Output struct {
		Audio struct {
			Data string `json:"data"`
		} `json:"audio"`
		FinishReason *string `json:"finish_reason"`
	} `json:"output"`
}

func NewAliYunTTS(apiKey string) *AliYunTTS {
	return &AliYunTTS{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

func (tts *AliYunTTS) setHeaders(req *http.Request) {
	req.Header.Add("Content-Type", aliyunContentType)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tts.apiKey))
	req.Header.Add("X-DashScope-SSE", "enable")
}

// getData 调用阿里云TTS
func (tts *AliYunTTS) getData(text string) ([]byte, error) {
	data, err := json.Marshal(&AliYunRequest{
		Model: aliyunModelName,
		Input: AliYunRequestInput{
			Text:         text,
			Voice:        aliyunVoiceName,
			LanguageType: aliyunLanguageType,
		},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, aliyunEndpoint, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	tts.setHeaders(req)
	resp, err := tts.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)

	var buffer bytes.Buffer
	for scanner.Scan() {
		data := &AliYunResponse{}
		rawBytes := scanner.Bytes()
		if !bytes.HasPrefix(rawBytes, []byte("data:")) {
			continue
		}
		err := json.Unmarshal(rawBytes[5:], data)
		if err != nil {
			continue
		}
		if data.Output.FinishReason != nil && *data.Output.FinishReason == "stop" {
			break
		}
		decodeString, err := base64.StdEncoding.DecodeString(data.Output.Audio.Data)
		if err != nil {
			return nil, err
		}
		buffer.Write(decodeString)
	}

	return buffer.Bytes(), nil
}

func (tts *AliYunTTS) Synthesize(text string) (audio []byte, err error) {
	if len(text) <= aliyunModelMaxLength {
		return tts.getData(text)
	}

	parts := strings.Split(text, ",")
	size := int(math.Ceil(float64(len(text)) / float64(aliyunModelMaxLength)))
	texts := make([]string, size)
	i := 0
	for _, part := range parts {
		if len(texts[i])+len(part)+1 > aliyunModelMaxLength {
			i++
		} else {
			texts[i] += ","
		}
		texts[i] += part
	}

	result := make([][]byte, size)
	errs := make([]error, size)
	wg := sync.WaitGroup{}
	for i, part := range texts {
		wg.Add(1)
		go func(i int, part string) {
			defer wg.Done()
			data, err := tts.getData(part)
			if err != nil {
				errs[i] = err
				return
			}
			result[i] = data
		}(i, part)
	}
	wg.Wait()

	if err := utils.Find(errs, func(err error) bool {
		return err != nil
	}); err != nil {
		return nil, err
	}

	return bytes.Join(result, nil), nil
}
