// Package service
package service

import (
	. "github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
)

var (
	SuccessGetServerConfig = NewApiStatus("GET_SERVER_CONFIG", "成功获取服务器配置", Ok)
	SuccessGetServerInfo   = NewApiStatus("GET_SERVER_INFO", "成功获取服务器信息", Ok)
	SuccessGetTimeRating   = NewApiStatus("GET_TIME_RATING", "成功获取服务器排行榜", Ok)
)

type ServerServiceInterface interface {
	GetServerConfig() *ApiResponse[*ResponseGetServerConfig]
	GetServerInfo() *ApiResponse[*ResponseGetServerInfo]
	GetTimeRating() *ApiResponse[*ResponseGetTimeRating]
}

type FileLimit struct {
	MaxAllowSize int      `json:"max_allow_size"`
	AllowedExt   []string `json:"allowed_ext"`
}

type ResponseGetServerConfig struct {
	ImageLimit        *FileLimit       `json:"image_limit"`
	FileLimit         *FileLimit       `json:"file_limit"`
	EmailSendInterval int              `json:"email_send_interval"`
	Facilities        []*FacilityModel `json:"facilities"`
	Ratings           []*RatingModel   `json:"ratings"`
}

type ResponseGetServerInfo struct {
	TotalUser       int64 `json:"total_user"`
	TotalController int64 `json:"total_controller"`
	TotalActivity   int64 `json:"total_activity"`
}

type OnlineTime struct {
	Cid       int    `json:"cid"`
	AvatarUrl string `json:"avatar_url"`
	Time      int    `json:"time"`
}

type ResponseGetTimeRating struct {
	Pilots      []*OnlineTime `json:"pilots"`
	Controllers []*OnlineTime `json:"controllers"`
}
