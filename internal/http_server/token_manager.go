// Package http_server
package http_server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/utils"
	"github.com/labstack/echo/v4"
)

const (
	ClientId      = "charts-rn-desktop"
	ClientSecret  = "igljsnfBunGqI706JnQRIkQuJB65iscC"
	DeviceAuthUrl = "https://identity.api.navigraph.com/connect/deviceauthorization"
	TokenUrl      = "https://identity.api.navigraph.com/connect/token"
	ClientScope   = "userinfo openid offline_access amdb charts email navdata userdata fmsdata tiles simbrief"
)

type TokenManager struct {
	logger                  log.LoggerInterface
	config                  *config.NavigraphConfig
	flushTokenFlushCallback func(flushToken string)
	token                   *TokenResponse
	expiresIn               time.Time
	initialized             bool
	client                  *http.Client
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	UserCode                string `json:"user_code"`
	VerificationUrl         string `json:"verification_uri"`
	VerificationUrlComplete string `json:"verification_uri_complete"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func addHeader(req *http.Request) {
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) NavigraphCharts/8.38.3 Chrome/106.0.5249.199 Electron/21.4.1 Safari/537.36")
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Host", "identity.api.navigraph.com")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept-Encoding", "gzip, deflate, br")
	req.Header.Add("Accept-Language", "zh-CN")
}

func NewTokenManager(
	logger log.LoggerInterface,
	config *config.NavigraphConfig,
	flushTokenFlushCallback func(flushToken string),
) *TokenManager {
	manager := &TokenManager{
		logger: log.NewLoggerAdapter(logger, "TokenManager"),
		config: config,
		token: &TokenResponse{
			RefreshToken: config.Token,
		},
		flushTokenFlushCallback: flushTokenFlushCallback,
		initialized:             false,
	}
	manager.client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}
	go func(m *TokenManager) {
		if m.refreshAccessToken() {
			m.logger.Info("Use cached flush token")
			m.initialized = true
			return
		}
		response, verifier := m.requestDeviceAuthorization()
		if response == nil {
			m.logger.Error("Request device authorization fail")
			return
		}
		go m.pollForAccessToken(response.DeviceCode, verifier, response.Interval, response.ExpiresIn)
	}(manager)
	return manager
}

func (m *TokenManager) requestDeviceAuthorization() (*DeviceAuthResponse, string) {
	payload := &url.Values{}
	payload.Add("client_id", ClientId)
	payload.Add("client_secret", ClientSecret)
	pkceGenerator := utils.NewPKCE()
	_ = pkceGenerator.GenerateCodeVerifier()
	pkceGenerator.GenerateCodeChallenge()
	verifier := pkceGenerator.GetCodeVerifier()
	payload.Add("code_challenge", pkceGenerator.GetCodeChallenge())
	payload.Add("code_challenge_method", pkceGenerator.GetChallengeMethod())
	req, _ := http.NewRequest("POST", DeviceAuthUrl, strings.NewReader(payload.Encode()))
	addHeader(req)
	res, err := m.client.Do(req)
	if err != nil {
		m.logger.ErrorF("device authorization network fail: %s", err.Error())
		return nil, ""
	}
	if res.StatusCode != http.StatusOK {
		m.logger.ErrorF("device authorization fail with http status %d", res.StatusCode)
		return nil, ""
	}
	response := &DeviceAuthResponse{}
	data, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err := json.Unmarshal(data, response); err != nil {
		m.logger.ErrorF("device authorization fail: %s", err.Error())
		return nil, ""
	}
	m.logger.InfoF("Device authorization, please visit %s to manual authorization", response.VerificationUrlComplete)
	return response, verifier
}

func (m *TokenManager) pollForAccessToken(deviceCode string, verifier string, interval int, expiresIn int) {
	intervalDuration := time.Duration(interval) * time.Second
	ticker := time.NewTicker(intervalDuration)
	defer ticker.Stop()

	timeout := time.After(time.Duration(expiresIn) * time.Second)

	for {
		select {
		case <-ticker.C:
			payload := &url.Values{}
			payload.Add("client_id", ClientId)
			payload.Add("client_secret", ClientSecret)
			payload.Add("code_verifier", verifier)
			payload.Add("device_code", deviceCode)
			payload.Add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			payload.Add("scope", ClientScope)
			req, _ := http.NewRequest("POST", TokenUrl, strings.NewReader(payload.Encode()))
			addHeader(req)
			res, err := m.client.Do(req)
			if err != nil {
				m.logger.ErrorF("pollForAccessToken Error: %s", err.Error())
				_ = res.Body.Close()
				return
			}
			data, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				errorResponse := &ErrorResponse{}
				if err := json.Unmarshal(data, errorResponse); err != nil {
					m.logger.ErrorF("pollForAccessToken Unmarshal Error: %s", err.Error())
					return
				}
				m.logger.ErrorF("Device authorization fail code %s : %s", errorResponse.Error, errorResponse.ErrorDescription)
				if errorResponse.Error == "authorization_pending" {
					continue
				} else if errorResponse.Error == "access_denied" {
					m.logger.Error("Device authorization fail: user denied")
					return
				} else if errorResponse.Error == "slow_down" {
					m.logger.Error("Device authorization fail: slow down")
					intervalDuration += 5 * time.Second
					ticker.Reset(intervalDuration)
					continue
				} else {
					m.logger.Error("Device authorization timeout")
					return
				}
			}
			token := &TokenResponse{}
			if err := json.Unmarshal(data, token); err != nil {
				m.logger.ErrorF("pollForAccessToken Unmarshal Error: %s", err.Error())
				return
			}
			m.token = token
			m.initialized = true
			m.flushTokenFlushCallback(token.RefreshToken)
			m.expiresIn = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
			m.logger.Info("Device authorization passed")
			return
		case <-timeout:
			m.logger.Error("Device authorization timeout")
			return
		}
	}
}

func (m *TokenManager) refreshAccessToken() bool {
	payload := &url.Values{}
	payload.Add("client_id", ClientId)
	payload.Add("client_secret", ClientSecret)
	payload.Add("refresh_token", m.token.RefreshToken)
	payload.Add("grant_type", "refresh_token")
	payload.Add("scope", ClientScope)
	req, _ := http.NewRequest("POST", TokenUrl, strings.NewReader(payload.Encode()))
	addHeader(req)
	res, err := m.client.Do(req)
	if err != nil {
		m.logger.ErrorF("refreshAccessToken Error: %s", err.Error())
		return false
	}
	if res.StatusCode != http.StatusOK {
		m.logger.ErrorF("refreshAccessToken StatusCode: %d", res.StatusCode)
		return false
	}
	token := &TokenResponse{}
	data, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err := json.Unmarshal(data, token); err != nil {
		m.logger.ErrorF("refreshAccessToken Unmarshal Error: %s", err.Error())
		return false
	}
	m.token = token
	m.flushTokenFlushCallback(token.RefreshToken)
	m.expiresIn = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	m.logger.Info("Refresh access token success")
	return true
}

func (m *TokenManager) HandleProxy(c echo.Context) error {
	if !m.initialized {
		return service.NewApiResponse[any](service.ErrNotAvailable, nil).Response(c)
	}

	originalRequest := c.Request()
	targetUrl := c.Param("*")

	req, err := http.NewRequest(originalRequest.Method, targetUrl, originalRequest.Body)
	if err != nil {
		m.logger.ErrorF("HandleProxy Error: %s", err.Error())
		return service.NewApiResponse[any](service.ErrCreateRequest, nil).Response(c)
	}

	for key, values := range originalRequest.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	req.Header.Set("Authorization", m.getAccessToken())

	resp, err := m.client.Do(req)
	if err != nil {
		m.logger.ErrorF("HandleProxy SendRequest Error: %s", err.Error())
		return service.NewApiResponse[any](service.ErrSendRequest, nil).Response(c)
	}

	for key, values := range resp.Header {
		for _, value := range values {
			c.Response().Header().Add(key, value)
		}
	}

	if resp.StatusCode == service.Unauthorized.Code() {
		m.logger.Error("HandleProxy Error: Token expired")
		return service.NewApiResponse[any](service.ErrTokenExpired, nil).Response(c)
	}

	c.Response().WriteHeader(resp.StatusCode)

	_, err = io.Copy(c.Response().Writer, resp.Body)
	_ = resp.Body.Close()

	if err != nil {
		m.logger.ErrorF("HandleProxy Error: %s", err.Error())
		return service.NewApiResponse[any](service.ErrCopyRequest, nil).Response(c)
	}

	return nil
}

func (m *TokenManager) getAccessToken() string {
	if !m.initialized {
		return ""
	}
	if time.Now().After(m.expiresIn) {
		m.refreshAccessToken()
	}
	return "Bearer " + m.token.AccessToken
}
