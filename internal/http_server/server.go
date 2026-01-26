// Package http_server
package http_server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/half-nothing/simple-fsd/internal/cache"
	"github.com/half-nothing/simple-fsd/internal/http_server/controller"
	mid "github.com/half-nothing/simple-fsd/internal/http_server/middleware"
	impl "github.com/half-nothing/simple-fsd/internal/http_server/service"
	"github.com/half-nothing/simple-fsd/internal/http_server/service/store"
	ws "github.com/half-nothing/simple-fsd/internal/http_server/websocket"
	. "github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/utils"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/samber/slog-echo"
	"golang.org/x/sync/errgroup"
)

type ShutdownCallback struct {
	serverHandler *echo.Echo
	websocket     *ws.WebSocketServer
}

func NewShutdownCallback(serverHandler *echo.Echo, websocket *ws.WebSocketServer) *ShutdownCallback {
	return &ShutdownCallback{
		serverHandler: serverHandler,
		websocket:     websocket,
	}
}

func (hc *ShutdownCallback) Invoke(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var eg errgroup.Group
	eg.Go(func() error { return hc.websocket.Close(timeoutCtx) })
	eg.Go(func() error { return hc.serverHandler.Shutdown(timeoutCtx) })
	return eg.Wait()
}

func StartHttpServer(applicationContent *ApplicationContent) {
	config := applicationContent.ConfigManager().Config()
	logger := applicationContent.Logger().HttpLogger()

	logger.Info("Http server initializing...")
	e := echo.New()
	e.Logger.SetOutput(io.Discard)
	e.Logger.SetLevel(log.OFF)
	httpConfig := config.Server.HttpServer

	messageQueue := applicationContent.MessageQueue()

	websocketServer := ws.NewWebSocketServer(logger, messageQueue, httpConfig)

	webSocketGroup := e.Group("/ws")
	webSocketGroup.GET("/fsd", websocketServer.ConnectToFsd)

	skipWebSocket := func(c echo.Context) bool {
		return strings.HasPrefix(c.Path(), "/ws")
	}

	skipCharts := func(c echo.Context) bool {
		return strings.HasPrefix(c.Path(), "/api/charts")
	}

	switch httpConfig.ProxyType {
	case 0:
		e.IPExtractor = echo.ExtractIPDirect()
	case 1:
		trustOperations := make([]echo.TrustOption, 0, len(config.Server.HttpServer.TrustedIpRange))
		for _, ip := range config.Server.HttpServer.TrustedIpRange {
			_, network, err := net.ParseCIDR(ip)
			if err != nil {
				logger.WarnF("%s is not a valid CIDR string, skipping it", ip)
				continue
			}
			trustOperations = append(trustOperations, echo.TrustIPRange(network))
		}
		e.IPExtractor = echo.ExtractIPFromXFFHeader(trustOperations...)
	case 2:
		e.IPExtractor = echo.ExtractIPFromRealIPHeader()
	default:
		logger.WarnF("Invalid proxy type %d, using default (direct)", httpConfig.ProxyType)
		e.IPExtractor = echo.ExtractIPDirect()
	}

	if config.Server.HttpServer.SSL.ForceSSL {
		e.Use(middleware.HTTPSRedirect())
	}

	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 30 * time.Second,
		Skipper: func(c echo.Context) bool {
			return skipWebSocket(c) || skipCharts(c)
		},
	}))
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		LogErrorFunc: func(ctx echo.Context, err error, stack []byte) error {
			logger.ErrorF("Recovered from a fatal error: %v, stack: %s", err, string(stack))
			return err
		},
	}))

	loggerConfig := slogecho.Config{
		DefaultLevel:     slog.LevelInfo,
		ClientErrorLevel: slog.LevelWarn,
		ServerErrorLevel: slog.LevelError,
	}
	e.Use(slogecho.NewWithConfig(logger.LogHandler(), loggerConfig))

	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            httpConfig.SSL.HstsExpiredTime,
		HSTSExcludeSubdomains: !httpConfig.SSL.IncludeDomain,
	}))

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     httpConfig.CORS.AllowOrigins,
		AllowMethods:     httpConfig.CORS.AllowMethods,
		AllowHeaders:     httpConfig.CORS.AllowHeaders,
		ExposeHeaders:    httpConfig.CORS.ExposeHeaders,
		AllowCredentials: httpConfig.CORS.AllowCredentials,
		MaxAge:           httpConfig.CORS.MaxAge,
	}))
	if httpConfig.BodyLimit != "" {
		e.Use(middleware.BodyLimit(httpConfig.BodyLimit))
	} else {
		logger.Warn("No body limit set, be aware of possible DDOS attacks")
	}
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level:   5,
		Skipper: skipWebSocket,
	}))

	if httpConfig.RateLimit != 0 {
		ipPathLimiter := utils.NewSlidingWindowLimiter(time.Minute, httpConfig.RateLimit)
		ipPathLimiter.StartCleanup(2 * time.Minute)
		e.Use(mid.RateLimitMiddleware(ipPathLimiter, mid.CombinedKeyFunc))
		logger.InfoF("Rate limit: %d requests per minute", httpConfig.RateLimit)
	} else {
		logger.Warn("No rate limit was set, be aware of possible DDOS attacks")
	}

	whazzupUrl, _ := url.JoinPath(httpConfig.ServerAddress, "/api/clients")
	whazzupContent := fmt.Sprintf("url0=%s", whazzupUrl)

	jwtConfig := echojwt.Config{
		SigningKey:    []byte(httpConfig.JWT.Secret),
		TokenLookup:   "header:Authorization:Bearer ",
		SigningMethod: global.SigningMethod,
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(service.Claims)
		},
		ErrorHandler: func(c echo.Context, err error) error {
			var data *service.ApiResponse[any]
			switch {
			case errors.Is(err, echojwt.ErrJWTMissing):
				data = service.NewApiResponse[any](service.ErrMissingOrMalformedJwt, nil)
			case errors.Is(err, echojwt.ErrJWTInvalid):
				data = service.NewApiResponse[any](service.ErrInvalidOrExpiredJwt, nil)
			default:
				data = service.NewApiResponse[any](service.ErrUnknownJwtError, nil)
			}
			return data.Response(c)
		},
	}

	jwtMiddleware := echojwt.WithConfig(jwtConfig)

	jwtVerifyMiddleWare := func(tokenTypes ...service.TokenType) echo.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx echo.Context) error {
				token := ctx.Get("user").(*jwt.Token)
				claim := token.Claims.(*service.Claims)
				if slices.Contains(tokenTypes, service.TokenType(claim.TokenType)) {
					return next(ctx)
				}
				return service.NewApiResponse[any](service.ErrInvalidJwtType, nil).Response(ctx)
			}
		}
	}

	requireMainToken := jwtVerifyMiddleWare(service.MainToken)
	requireMainRefreshToken := jwtVerifyMiddleWare(service.MainRefreshToken)
	requireMainTokenOrOAuthToken := jwtVerifyMiddleWare(service.MainToken, service.OAuth2Token)
	requireOAuthToken := jwtVerifyMiddleWare(service.OAuth2Token)

	logger.Info("Service initializing...")

	userOperation := applicationContent.Operations().UserOperation()
	controllerOperation := applicationContent.Operations().ControllerOperation()
	controllerRecordOperation := applicationContent.Operations().ControllerRecordOperation()
	controllerApplicationOperation := applicationContent.Operations().ControllerApplicationOperation()
	historyOperation := applicationContent.Operations().HistoryOperation()
	auditLogOperation := applicationContent.Operations().AuditLogOperation()
	activityOperation := applicationContent.Operations().ActivityOperation()
	ticketOperation := applicationContent.Operations().TicketOperation()
	flightPlanOperation := applicationContent.Operations().FlightPlanOperation()
	announcementOperation := applicationContent.Operations().AnnouncementOperation()
	oauth2Operation := applicationContent.Operations().OAuth2Operation()
	metarManager := applicationContent.MetarManager()

	auditLogService := impl.NewAuditService(logger, auditLogOperation)
	messageQueue.Subscribe(queue.AuditLog, auditLogService.HandleAuditLogMessage)
	messageQueue.Subscribe(queue.AuditLogs, auditLogService.HandleAuditLogsMessage)

	clientManager := applicationContent.ClientManager()

	var storeService service.StoreServiceInterface
	storeService = store.NewLocalStoreService(logger, httpConfig.Store, messageQueue, auditLogOperation)
	switch httpConfig.Store.StoreType {
	case 1:
		storeService = store.NewALiYunOssStoreService(logger, httpConfig.Store, storeService, messageQueue, auditLogOperation)
	case 2:
		storeService = store.NewTencentCosStoreService(logger, httpConfig.Store, storeService, messageQueue, auditLogOperation)
	}

	emailCodesCache := cache.NewMemoryCache[*service.EmailCode](config.Server.HttpServer.Email.VerifyExpiredDuration)
	defer emailCodesCache.Close()
	lastSendTimeCache := cache.NewMemoryCache[time.Time](config.Server.HttpServer.Email.SendDuration)
	defer lastSendTimeCache.Close()
	emailService := impl.NewEmailService(logger, config.Server.HttpServer.Email, emailCodesCache, lastSendTimeCache, userOperation, messageQueue)

	messageQueue.Subscribe(queue.DeleteVerifyCode, emailService.HandleDeleteVerifyCodeMessage)

	userService := impl.NewUserService(logger, httpConfig, messageQueue, userOperation, historyOperation, auditLogOperation, storeService, emailService)
	clientService := impl.NewClientService(logger, httpConfig, userOperation, auditLogOperation, clientManager, messageQueue)
	serverService := impl.NewServerService(logger, config.Server, userOperation, controllerOperation, activityOperation)
	activityService := impl.NewActivityService(logger, httpConfig, messageQueue, userOperation, activityOperation, auditLogOperation, storeService)
	controllerService := impl.NewControllerService(logger, httpConfig, messageQueue, userOperation, controllerOperation, controllerRecordOperation, auditLogOperation)
	controllerApplicationService := impl.NewControllerApplicationService(logger, messageQueue, controllerApplicationOperation, userOperation, auditLogOperation)
	ticketService := impl.NewTicketService(logger, messageQueue, userOperation, ticketOperation, auditLogOperation)
	flightPlanService := impl.NewFlightPlanService(logger, messageQueue, userOperation, flightPlanOperation, auditLogOperation)
	announcementService := impl.NewAnnouncementService(logger, messageQueue, announcementOperation, auditLogOperation)
	oauth2Service := impl.NewOAuth2Service(logger, httpConfig, messageQueue, oauth2Operation, userOperation, auditLogOperation)
	metarService := impl.NewMetarService(logger, metarManager)

	logger.Info("Controller initializing...")

	userController := controller.NewUserHandler(logger, userService)
	emailController := controller.NewEmailController(logger, emailService)
	clientController := controller.NewClientController(logger, clientService)
	serverController := controller.NewServerController(logger, serverService)
	activityController := controller.NewActivityController(logger, activityService)
	fileController := controller.NewFileController(logger, storeService)
	auditLogController := controller.NewAuditLogController(logger, auditLogService)
	controllerController := controller.NewATCController(logger, controllerService)
	controllerApplicationController := controller.NewControllerApplicationController(logger, controllerApplicationService)
	ticketController := controller.NewTicketController(logger, ticketService)
	flightPlanController := controller.NewFlightPlanController(logger, flightPlanService)
	announcementController := controller.NewAnnouncementController(logger, announcementService)
	oauth2Controller := controller.NewOAuth2Controller(logger, httpConfig.OAuth2, oauth2Service)
	metarServiceController := controller.NewMetarServiceController(logger, metarService)

	logger.Info("Applying router...")

	data := service.NewApiResponse(
		service.NewApiStatus("SUCCESS_GET_VERSION", "成功获取版本信息", service.Ok),
		&service.VersionInfo{
			BuildTime:  global.BuildTime,
			GitVersion: global.GitVersion,
			GitCommit:  global.GitCommit,
			Version:    global.AppVersion,
		},
	)
	apiGroup := e.Group("/api")
	apiGroup.POST("/codes", emailController.SendVerifyEmail)
	apiGroup.GET("/metar", metarServiceController.QueryMetar)
	apiGroup.GET("/version", func(ctx echo.Context) error { return data.Response(ctx) })

	userGroup := apiGroup.Group("/users")
	userGroup.POST("", userController.UserRegister)
	userGroup.GET("", userController.GetUsers, jwtMiddleware, requireMainToken)
	userGroup.POST("/sessions", userController.UserLogin)
	userGroup.POST("/sessions/fsd", userController.UserFsdLogin)
	userGroup.GET("/sessions/fsd", userController.UserFsdToken, jwtMiddleware, requireMainToken)
	userGroup.GET("/sessions", userController.GetToken, jwtMiddleware, requireMainRefreshToken)
	userGroup.GET("/availability", userController.CheckUserAvailability)
	userGroup.GET("/histories/self", userController.GetUserHistory, jwtMiddleware, requireMainToken)
	userGroup.GET("/profiles/self", userController.GetCurrentUserProfile, jwtMiddleware, requireMainTokenOrOAuthToken)
	userGroup.PATCH("/profiles/self", userController.EditCurrentProfile, jwtMiddleware, requireMainToken)
	userGroup.GET("/profiles/:uid", userController.GetUserProfile, jwtMiddleware, requireMainToken)
	userGroup.PATCH("/profiles/:uid", userController.EditProfile, jwtMiddleware, requireMainToken)
	userGroup.PATCH("/profiles/:uid/permission", userController.EditUserPermission, jwtMiddleware, requireMainToken)
	userGroup.POST("/password", userController.ResetUserPassword)

	controllerGroup := apiGroup.Group("/controllers")
	controllerGroup.GET("", controllerController.GetControllers, jwtMiddleware, requireMainToken)
	controllerGroup.GET("/ratings", controllerController.GetControllerRatings)
	controllerGroup.GET("/records/self", controllerController.GetCurrentControllerRecord, jwtMiddleware, requireMainToken)
	controllerGroup.GET("/records/:uid", controllerController.GetControllerRecord, jwtMiddleware, requireMainToken)
	controllerGroup.POST("/records/:uid", controllerController.AddControllerRecord, jwtMiddleware, requireMainToken)
	controllerGroup.DELETE("/records/:uid/:rid", controllerController.DeleteControllerRecord, jwtMiddleware, requireMainToken)
	controllerGroup.PUT("/:uid/rating", controllerController.UpdateControllerRating, jwtMiddleware, requireMainToken)

	applicationGroup := controllerGroup.Group("/applications")
	applicationGroup.GET("", controllerApplicationController.GetApplications, jwtMiddleware, requireMainToken)
	applicationGroup.GET("/self", controllerApplicationController.GetSelfApplication, jwtMiddleware, requireMainToken)
	applicationGroup.POST("", controllerApplicationController.SubmitApplication, jwtMiddleware, requireMainToken)
	applicationGroup.PUT("/:aid", controllerApplicationController.UpdateApplication, jwtMiddleware, requireMainToken)
	applicationGroup.DELETE("/self", controllerApplicationController.CancelSelfApplication, jwtMiddleware, requireMainToken)

	clientGroup := apiGroup.Group("/clients")
	clientGroup.GET("", clientController.GetOnlineClients)
	clientGroup.GET("/status", func(c echo.Context) error { return c.String(http.StatusOK, whazzupContent) })
	clientGroup.GET("/paths/:callsign", clientController.GetClientPath, jwtMiddleware, requireMainToken)
	clientGroup.POST("/messages", clientController.BroadcastMessage, jwtMiddleware, requireMainToken)
	clientGroup.POST("/messages/:callsign", clientController.SendMessageToClient, jwtMiddleware, requireMainToken)
	clientGroup.DELETE("/:callsign", clientController.KillClient, jwtMiddleware, requireMainToken)

	serverGroup := apiGroup.Group("/server")
	serverGroup.GET("/config", serverController.GetServerConfig)
	serverGroup.GET("/info", serverController.GetServerInfo, jwtMiddleware, requireMainToken)
	serverGroup.GET("/rating", serverController.GetServerOnlineTime, jwtMiddleware, requireMainToken)

	activityGroup := apiGroup.Group("/activities")
	activityGroup.GET("", activityController.GetActivities, jwtMiddleware, requireMainToken)
	activityGroup.GET("/pages", activityController.GetActivitiesPage, jwtMiddleware, requireMainToken)
	activityGroup.GET("/:activity_id", activityController.GetActivityInfo, jwtMiddleware, requireMainToken)
	activityGroup.POST("", activityController.AddActivity, jwtMiddleware, requireMainToken)
	activityGroup.DELETE("/:activity_id", activityController.DeleteActivity, jwtMiddleware, requireMainToken)
	activityGroup.POST("/:activity_id/controllers/:facility_id", activityController.ControllerJoin, jwtMiddleware, requireMainToken)
	activityGroup.DELETE("/:activity_id/controllers/:facility_id", activityController.ControllerLeave, jwtMiddleware, requireMainToken)
	activityGroup.POST("/:activity_id/pilots", activityController.PilotJoin, jwtMiddleware, requireMainToken)
	activityGroup.DELETE("/:activity_id/pilots", activityController.PilotLeave, jwtMiddleware, requireMainToken)
	activityGroup.PUT("/:activity_id/status", activityController.EditActivityStatus, jwtMiddleware, requireMainToken)
	activityGroup.PUT("/:activity_id/pilots/:user_id/status", activityController.EditPilotStatus, jwtMiddleware, requireMainToken)
	activityGroup.PUT("/:activity_id", activityController.EditActivity, jwtMiddleware, requireMainToken)

	ticketGroup := apiGroup.Group("/tickets")
	ticketGroup.GET("", ticketController.GetTickets, jwtMiddleware, requireMainToken)
	ticketGroup.GET("/self", ticketController.GetUserTickets, jwtMiddleware, requireMainToken)
	ticketGroup.POST("", ticketController.CreateTicket, jwtMiddleware, requireMainToken)
	ticketGroup.PUT("/:tid", ticketController.CloseTicket, jwtMiddleware, requireMainToken)
	ticketGroup.DELETE("/:tid", ticketController.DeleteTicket, jwtMiddleware, requireMainToken)

	flightPlanGroup := apiGroup.Group("/plans")
	flightPlanGroup.POST("", flightPlanController.SubmitFlightPlan, jwtMiddleware, requireMainToken)
	flightPlanGroup.GET("", flightPlanController.GetFlightPlans, jwtMiddleware, requireMainToken)
	flightPlanGroup.GET("/self", flightPlanController.GetFlightPlan, jwtMiddleware, requireMainToken)
	flightPlanGroup.DELETE("/self", flightPlanController.DeleteSelfFlightPlan, jwtMiddleware, requireMainToken)
	flightPlanGroup.PUT("/:cid/lock", flightPlanController.LockFlightPlan, jwtMiddleware, requireMainToken)
	flightPlanGroup.DELETE("/:cid/lock", flightPlanController.UnlockFlightPlan, jwtMiddleware, requireMainToken)
	flightPlanGroup.DELETE("/:cid", flightPlanController.DeleteFlightPlan, jwtMiddleware, requireMainToken)

	announcementGroup := apiGroup.Group("/announcements")
	announcementGroup.GET("", announcementController.GetAnnouncements, jwtMiddleware, requireMainToken)
	announcementGroup.GET("/detail", announcementController.GetDetailAnnouncements, jwtMiddleware, requireMainToken)
	announcementGroup.POST("", announcementController.CreateAnnouncement, jwtMiddleware, requireMainToken)
	announcementGroup.PUT("/:aid", announcementController.UpdateAnnouncement, jwtMiddleware, requireMainToken)
	announcementGroup.DELETE("/:aid", announcementController.DeleteAnnouncement, jwtMiddleware, requireMainToken)

	fileGroup := apiGroup.Group("/files")
	fileGroup.POST("/images", fileController.UploadImage, jwtMiddleware, requireMainToken)
	fileGroup.POST("/files", fileController.UploadFile, jwtMiddleware, requireMainToken)

	auditLogGroup := apiGroup.Group("/audits")
	auditLogGroup.GET("", auditLogController.GetAuditLogs, jwtMiddleware, requireMainToken)
	auditLogGroup.POST("/unlawful_overreach", auditLogController.LogUnlawfulOverreach, jwtMiddleware, requireMainToken)

	// OAuth2路由
	oauth2Group := apiGroup.Group("/oauth")
	if httpConfig.OAuth2.Enabled {
		oauth2Group.POST("/clients", oauth2Controller.CreateClient, jwtMiddleware, requireMainToken)
		oauth2Group.GET("/clients", oauth2Controller.GetClientPage, jwtMiddleware, requireMainToken)
		oauth2Group.PATCH("/clients/:client_id", oauth2Controller.UpdateClient, jwtMiddleware, requireMainToken)
		oauth2Group.DELETE("/clients/:client_id", oauth2Controller.DeleteClient, jwtMiddleware, requireMainToken)

		oauth2Group.PUT("/authorization/:id", oauth2Controller.PutAuthorization, jwtMiddleware, requireMainToken)
		oauth2Group.GET("/authorization/:id", oauth2Controller.GetAuthorization, jwtMiddleware, requireMainToken)
		oauth2Group.GET("/authorize", oauth2Controller.Authorize)
		oauth2Group.POST("/token", oauth2Controller.Token)
		oauth2Group.POST("/revoke", oauth2Controller.Revoke, jwtMiddleware, requireOAuthToken)
	} else {
		oauth2Group.Any("/*", func(c echo.Context) error {
			return service.NewJsonResponse(c, service.NotImplemented, &service.OAuth2ErrorResponse{
				ErrorCode:        service.OAuth2ErrTemporarilyUnavailable.ErrorCode,
				ErrorDescription: "OAuth2 is not available on this server",
			})
		})
	}

	chartGroup := apiGroup.Group("/charts")

	if !config.Server.HttpServer.Navigraph.Enabled {
		chartGroup.Any("/*", func(c echo.Context) error {
			return service.NewApiResponse[any](service.ErrNotAvailable, nil).Response(c)
		})
	} else {
		tokenManager := NewTokenManager(applicationContent.Logger().MainLogger(), config.Server.HttpServer.Navigraph, func(flushToken string) {
			config.Server.HttpServer.Navigraph.Token = flushToken
			_ = applicationContent.ConfigManager().SaveConfig()
		})

		chartGroup.Any("/*", tokenManager.HandleProxy, jwtMiddleware, requireMainToken)
	}

	apiGroup.Use(middleware.Static(httpConfig.Store.LocalStorePath))

	applicationContent.Cleaner().Add(NewShutdownCallback(e, websocketServer))

	protocol := "http"
	if httpConfig.SSL.Enable {
		protocol = "https"
	}
	logger.InfoF("Starting %s server on %s", protocol, httpConfig.Address)

	var err error
	if httpConfig.SSL.Enable {
		err = e.StartTLS(
			httpConfig.Address,
			httpConfig.SSL.CertFile,
			httpConfig.SSL.KeyFile,
		)
	} else {
		err = e.Start(httpConfig.Address)
	}

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.FatalF("Http server error: %v", err)
	}
}
