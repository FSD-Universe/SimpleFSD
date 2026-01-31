package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/half-nothing/simple-fsd/internal/base"
	"github.com/half-nothing/simple-fsd/internal/cache"
	"github.com/half-nothing/simple-fsd/internal/database"
	"github.com/half-nothing/simple-fsd/internal/email"
	"github.com/half-nothing/simple-fsd/internal/fsd_server"
	"github.com/half-nothing/simple-fsd/internal/fsd_server/client"
	"github.com/half-nothing/simple-fsd/internal/http_server"
	"github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/message"
	"github.com/half-nothing/simple-fsd/internal/metar"
	"github.com/half-nothing/simple-fsd/internal/utils"
	"github.com/half-nothing/simple-fsd/internal/voice_server"
)

func recoverFromError() {
	if r := recover(); r != nil {
		fmt.Printf("It looks like there are some serious errors, the details are as follows: \n%v", r)
	}
}

func checkStringEnv(envKey string, target *string) {
	value := os.Getenv(envKey)
	if value != "" {
		*target = value
	}
}

func checkIntEnv(envKey string, target *int, defaultValue int) {
	value := os.Getenv(envKey)
	if value != "" {
		*target = utils.StrToInt(value, defaultValue)
	}
}

func checkBoolEnv(envKey string, target *bool) {
	value := os.Getenv(envKey)
	if val, err := strconv.ParseBool(value); err == nil && val {
		*target = true
	}
}

func checkDurationEnv(envKey string, target *time.Duration) {
	value := os.Getenv(envKey)
	if duration, err := time.ParseDuration(value); err == nil {
		*target = duration
	}
}

func main() {
	flag.Parse()

	checkBoolEnv(global.EnvDebugMode, global.DebugMode)
	checkStringEnv(global.EnvConfigFilePath, global.ConfigFilePath)
	checkBoolEnv(global.EnvSkipEmailVerification, global.SkipEmailVerification)
	checkBoolEnv(global.EnvUpdateConfig, global.UpdateConfig)
	checkBoolEnv(global.EnvNoLogs, global.NoLogs)
	checkIntEnv(global.EnvMessageQueueChannelSize, global.MessageQueueChannelSize, 128)
	checkStringEnv(global.EnvDownloadPrefix, global.DownloadPrefix)
	checkDurationEnv(global.EnvMetarCacheCleanInterval, global.MetarCacheCleanInterval)
	checkIntEnv(global.EnvMetarQueryThread, global.MetarQueryThread, 32)
	checkIntEnv(global.EnvFsdRecordFilter, global.FsdRecordFilter, 10)
	checkBoolEnv(global.EnvVatsimProtocol, global.Vatsim)
	checkBoolEnv(global.EnvVatsimFullProtocol, global.VatsimFull)
	checkBoolEnv(global.EnvMutilThread, global.MutilThread)
	checkBoolEnv(global.EnvVisualPilot, global.VisualPilot)
	checkDurationEnv(global.EnvWebsocketHeartbeatInterval, global.WebsocketHeartbeatInterval)
	checkDurationEnv(global.EnvWebsocketTimeout, global.WebsocketTimeout)
	checkIntEnv(global.EnvWebsocketMessageChannelSize, global.WebsocketMessageChannelSize, 128)
	checkIntEnv(global.EnvVoicePoolSize, global.VoicePoolSize, 128)

	if *global.VatsimFull {
		*global.Vatsim = true
	}

	defer recoverFromError()

	mainLogger := base.NewLogger()
	mainLogger.Init(global.MainLogPath, global.MainLogName, *global.DebugMode, *global.NoLogs)

	fsdLogger := base.NewLogger()
	fsdLogger.Init(global.FsdLogPath, global.FsdLogName, *global.DebugMode, *global.NoLogs)

	httpLogger := base.NewLogger()
	httpLogger.Init(global.HttpLogPath, global.HttpLogName, *global.DebugMode, *global.NoLogs)

	grpcLogger := base.NewLogger()
	grpcLogger.Init(global.GrpcLogPath, global.GrpcLogName, *global.DebugMode, *global.NoLogs)

	voiceLogger := base.NewLogger()
	voiceLogger.Init(global.VoiceLogPath, global.VoiceLogName, *global.DebugMode, *global.NoLogs)

	logger := log.NewLoggers(mainLogger, fsdLogger, httpLogger, grpcLogger, voiceLogger)

	mainLogger.Info("Application initializing...")

	mainLogger.Info("Reading configuration...")
	configManager := base.NewManager(mainLogger)
	config := configManager.Config()

	mainLogger.Info("Creating cleaner...")
	cleaner := base.NewCleaner(mainLogger)
	cleaner.Init()
	defer cleaner.Clean()

	cleaner.Add(fsdLogger.ShutdownCallback())
	cleaner.Add(httpLogger.ShutdownCallback())
	cleaner.Add(grpcLogger.ShutdownCallback())
	cleaner.Add(voiceLogger.ShutdownCallback())

	if err := fsd.SyncRatingConfig(config); err != nil {
		mainLogger.FatalF("Error occurred while handle rating addition, details: %v", err)
		return
	}

	if err := fsd.SyncFacilityConfig(config); err != nil {
		mainLogger.FatalF("Error occurred while handle facility addition, details: %v", err)
		return
	}

	fsd.SyncRangeLimit(config.Server.FSDServer.RangeLimit)

	mainLogger.Info("Connecting to database...")
	shutdownCallback, databaseOperation, err := database.ConnectDatabase(mainLogger, config, *global.DebugMode)
	if err != nil {
		mainLogger.FatalF("Error occurred while initializing operation, details: %v", err)
		return
	}
	cleaner.Add(shutdownCallback)

	mainLogger.InfoF("Initialize message queue with channel size %d", *global.MessageQueueChannelSize)
	messageQueue := message.NewAsyncMessageQueue(mainLogger, *global.MessageQueueChannelSize)

	cleaner.Add(messageQueue.ShutdownCallback())

	connectionManager := client.NewConnectionManager(fsdLogger)
	clientManager := client.NewClientManager(fsdLogger, config, connectionManager, messageQueue)

	messageQueue.Subscribe(queue.KickClientFromServer, clientManager.HandleKickClientFromServerMessage)
	messageQueue.Subscribe(queue.SendMessageToClient, clientManager.HandleSendMessageToClientMessage)
	messageQueue.Subscribe(queue.BroadcastMessage, clientManager.HandleBroadcastMessage)
	messageQueue.Subscribe(queue.FlushFlightPlan, clientManager.HandleFlightPlanFlushMessage)
	messageQueue.Subscribe(queue.ChangeFlightPlanLockStatus, clientManager.HandleLockChangeMessage)

	emailSender := email.NewEmailSender(mainLogger, config.Server.HttpServer.Email)
	emailMessageHandler := email.NewEmailMessageHandler(emailSender)

	messageQueue.Subscribe(queue.SendApplicationPassedEmail, emailMessageHandler.HandleSendApplicationPassedEmailMessage)
	messageQueue.Subscribe(queue.SendApplicationProcessingEmail, emailMessageHandler.HandleSendApplicationProcessingEmailMessage)
	messageQueue.Subscribe(queue.SendApplicationRejectedEmail, emailMessageHandler.HandleSendApplicationRejectedEmailMessage)
	messageQueue.Subscribe(queue.SendAtcRatingChangeEmail, emailMessageHandler.HandleSendAtcRatingChangeEmailMessage)
	messageQueue.Subscribe(queue.SendEmailVerifyEmail, emailMessageHandler.HandleSendEmailVerifyEmailMessage)
	messageQueue.Subscribe(queue.SendKickedFromServerEmail, emailMessageHandler.HandleSendKickedFromServerEmailMessage)
	messageQueue.Subscribe(queue.SendPasswordChangeEmail, emailMessageHandler.HandleSendPasswordChangeEmailMessage)
	messageQueue.Subscribe(queue.SendPasswordResetEmail, emailMessageHandler.HandleSendPasswordResetEmailMessage)
	messageQueue.Subscribe(queue.SendPermissionChangeEmail, emailMessageHandler.HandleSendPermissionChangeEmailMessage)
	messageQueue.Subscribe(queue.SendTicketReplyEmail, emailMessageHandler.HandleSendTicketReplyEmailMessage)

	memoryCache := cache.NewMemoryCache[*string](*global.MetarCacheCleanInterval)
	defer memoryCache.Close()

	metarManager := metar.NewMetarManager(mainLogger, config.MetarSource, memoryCache)

	mainLogger.Info("Creating application content...")
	applicationContent := interfaces.NewApplicationContent(
		logger,
		cleaner,
		configManager,
		clientManager,
		connectionManager,
		messageQueue,
		metarManager,
		databaseOperation,
	)

	mainLogger.Info("Application initialized. Starting application...")

	if config.Server.HttpServer.Enabled {
		go http_server.StartHttpServer(applicationContent)
	}

	if config.Server.VoiceServer.Enabled {
		voiceServer := voice_server.NewVoiceServer(applicationContent)
		go func() { _ = voiceServer.Start() }()
	}

	//if config.Server.GRPCServer.Enabled {
	//	go grpc_server.StartGRPCServer(applicationContent)
	//}

	fsd_server.StartFSDServer(applicationContent)
}
