// Package service
// 存放 ServerServiceInterface 的实现
package service

import (
	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type ServerService struct {
	logger              log.LoggerInterface
	config              *config.ServerConfig
	userOperation       operation.UserOperationInterface
	controllerOperation operation.ControllerOperationInterface
	activityOperation   operation.ActivityOperationInterface
	serverConfig        *utils.CachedValue[*ResponseGetServerConfig]
	serverInfo          *utils.CachedValue[*ResponseGetServerInfo]
	serverOnlineTime    *utils.CachedValue[*ResponseGetTimeRating]
}

func NewServerService(
	logger log.LoggerInterface,
	config *config.ServerConfig,
	userOperation operation.UserOperationInterface,
	controllerOperation operation.ControllerOperationInterface,
	activityOperation operation.ActivityOperationInterface,
) *ServerService {
	service := &ServerService{
		logger:              log.NewLoggerAdapter(logger, "ServerService"),
		config:              config,
		userOperation:       userOperation,
		controllerOperation: controllerOperation,
		activityOperation:   activityOperation,
	}
	service.serverConfig = utils.NewCachedValue(0, func() *ResponseGetServerConfig { return service.getServerConfig() })
	service.serverInfo = utils.NewCachedValue(config.FSDServer.CacheDuration, func() *ResponseGetServerInfo { return service.getServerInfo() })
	service.serverOnlineTime = utils.NewCachedValue(config.FSDServer.CacheDuration, func() *ResponseGetTimeRating { return service.getTimeRating() })
	return service
}

func (serverService *ServerService) getServerConfig() *ResponseGetServerConfig {
	return &ResponseGetServerConfig{
		ImageLimit: &FileLimit{
			MaxAllowSize: int(serverService.config.HttpServer.Store.FileLimit.ImageLimit.MaxFileSize),
			AllowedExt:   serverService.config.HttpServer.Store.FileLimit.ImageLimit.AllowedFileExt,
		},
		FileLimit: &FileLimit{
			MaxAllowSize: int(serverService.config.HttpServer.Store.FileLimit.FileLimit.MaxFileSize),
			AllowedExt:   serverService.config.HttpServer.Store.FileLimit.FileLimit.AllowedFileExt,
		},
		EmailSendInterval: int(serverService.config.HttpServer.Email.SendDuration.Seconds()),
		Facilities:        fsd.Facilities,
		Ratings:           fsd.Ratings,
	}
}

func (serverService *ServerService) getServerInfo() *ResponseGetServerInfo {
	totalUser, err := serverService.userOperation.GetTotalUsers()
	if err != nil {
		serverService.logger.ErrorF("ServerService.GetTotalUsers error: %v", err)
		totalUser = 0
	}
	totalControllers, err := serverService.controllerOperation.GetTotalControllers()
	if err != nil {
		serverService.logger.ErrorF("ServerService.GetTotalControllers error: %v", err)
		totalControllers = 0
	}
	totalActivities, err := serverService.activityOperation.GetTotalActivities()
	if err != nil {
		serverService.logger.ErrorF("ServerService.GetTotalActivities error: %v", err)
		totalActivities = 0
	}
	return &ResponseGetServerInfo{
		TotalUser:       totalUser,
		TotalController: totalControllers,
		TotalActivity:   totalActivities,
	}
}

func (serverService *ServerService) getTimeRating() *ResponseGetTimeRating {
	pilots, controllers, err := serverService.userOperation.GetTimeRatings()
	if err != nil {
		serverService.logger.ErrorF("ServerService.GetTimeRatings error: %v", err)
		return &ResponseGetTimeRating{}
	}
	data := &ResponseGetTimeRating{
		Pilots:      make([]*OnlineTime, 0),
		Controllers: make([]*OnlineTime, 0),
	}
	for _, pilot := range pilots {
		data.Pilots = append(data.Pilots, &OnlineTime{
			Cid:       pilot.Cid,
			AvatarUrl: pilot.AvatarUrl,
			Time:      pilot.TotalPilotTime,
		})
	}
	for _, controller := range controllers {
		data.Controllers = append(data.Controllers, &OnlineTime{
			Cid:       controller.Cid,
			AvatarUrl: controller.AvatarUrl,
			Time:      controller.TotalAtcTime,
		})
	}
	return data
}

func (serverService *ServerService) GetServerConfig() *ApiResponse[*ResponseGetServerConfig] {
	return NewApiResponse(SuccessGetServerConfig, serverService.serverConfig.GetValue())
}

func (serverService *ServerService) GetServerInfo() *ApiResponse[*ResponseGetServerInfo] {
	return NewApiResponse(SuccessGetServerInfo, serverService.serverInfo.GetValue())
}

func (serverService *ServerService) GetTimeRating() *ApiResponse[*ResponseGetTimeRating] {
	return NewApiResponse(SuccessGetTimeRating, serverService.serverOnlineTime.GetValue())
}
