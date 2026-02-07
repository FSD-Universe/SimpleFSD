// Package global
package global

import (
	"flag"
	"time"
)

var BuildTime = "unknown"
var GitCommit = "unknown"
var GitVersion = "unknown"

var (
	DebugMode                   = flag.Bool("debug", false, "Enable debug mode")
	ConfigFilePath              = flag.String("config", "./config.json", "Path to configuration file")
	SkipEmailVerification       = flag.Bool("skip-email-verification", false, "Skip email verification")
	UpdateConfig                = flag.Bool("update-config", false, "Auto update configuration")
	NoLogs                      = flag.Bool("no-logs", false, "Disable logging to file")
	MessageQueueChannelSize     = flag.Int("message-queue-channel-size", 128, "Message Queue channel size")
	DownloadPrefix              = flag.String("download-prefix", "https://raw.githubusercontent.com/Flyleague-Collection/SimpleFSD/refs/heads/main", "auto download prefix")
	MetarCacheCleanInterval     = flag.Duration("metar-cache-clean-interval", 30*time.Minute, "metar cache cleanup interval")
	MetarQueryThread            = flag.Int("metar-query-thread", 32, "metar query thread")
	FsdRecordFilter             = flag.Int("fsd-record-filter", 10, "record the minimum amount of time in the connection history")
	Vatsim                      = flag.Bool("vatsim", false, "Enable Vatsim protocol")
	VatsimFull                  = flag.Bool("vatsim-full", false, "Enable Full Vatsim protocol")
	MutilThread                 = flag.Bool("mutil-thread", false, "Enable Mutil thread")
	VisualPilot                 = flag.Bool("visual-pilot", false, "Enable Visual Pilot point")
	WebsocketHeartbeatInterval  = flag.Duration("websocket-heartbeat-interval", 30*time.Second, "Websocket heartbeat interval")
	WebsocketTimeout            = flag.Duration("websocket-timeout", 60*time.Second, "Websocket timeout")
	WebsocketMessageChannelSize = flag.Int("websocket-message-channel-size", 128, "Websocket message channel size")
	VoicePoolSize               = flag.Int("voice-pool-size", 128, "Voice pool size")
)

const (
	AppVersion    = "0.9.1"
	ConfigVersion = "0.9.5"

	SigningMethod = "HS512"

	EnvDebugMode                   = "DEBUG_MODE"
	EnvConfigFilePath              = "CONFIG_FILE_PATH"
	EnvSkipEmailVerification       = "SKIP_EMAIL_VERIFICATION"
	EnvUpdateConfig                = "UPDATE_CONFIG"
	EnvNoLogs                      = "NO_LOGS"
	EnvMessageQueueChannelSize     = "MESSAGE_QUEUE_CHANNEL_SIZE"
	EnvDownloadPrefix              = "DOWNLOAD_PREFIX"
	EnvMetarCacheCleanInterval     = "METAR_CACHE_CLEAN_INTERVAL"
	EnvMetarQueryThread            = "METAR_QUERY_THREAD"
	EnvFsdRecordFilter             = "FSD_RECORD_FILTER"
	EnvVatsimProtocol              = "VATSIM"
	EnvVatsimFullProtocol          = "VATSIM_FULL"
	EnvMutilThread                 = "MUTAR_THREAD"
	EnvVisualPilot                 = "VISUAL_PILOT"
	EnvWebsocketHeartbeatInterval  = "WEBSOCKET_HEART_INTERVAL"
	EnvWebsocketTimeout            = "WEBSOCKET_TIMEOUT"
	EnvWebsocketMessageChannelSize = "WEBSOCKET_MESSAGE_CHANNEL_SIZE"
	EnvVoicePoolSize               = "VOICE_POOL_SIZE"

	LogFilePath  = "logs"
	MainLogName  = "main"
	MainLogPath  = LogFilePath + "/" + MainLogName + ".log"
	FsdLogName   = "fsd"
	FsdLogPath   = LogFilePath + "/" + FsdLogName + ".log"
	HttpLogName  = "http"
	HttpLogPath  = LogFilePath + "/" + HttpLogName + ".log"
	GrpcLogName  = "grpc"
	GrpcLogPath  = LogFilePath + "/" + GrpcLogName + ".log"
	VoiceLogName = "voice"
	VoiceLogPath = LogFilePath + "/" + VoiceLogName + ".log"

	AirportDataFilePath                   = "/data/airport.json"
	EmailVerifyTemplateFilePath           = "/template/email_verify.template"
	ATCRatingChangeTemplateFilePath       = "/template/atc_rating_change.template"
	PermissionChangeTemplateFilePath      = "/template/permission_change.template"
	KickedFromServerTemplateFilePath      = "/template/kicked_from_server.template"
	PasswordChangeTemplateFilePath        = "/template/password_change.template"
	PasswordResetTemplateFilePath         = "/template/password_reset.template"
	ApplicationPassedTemplateFilePath     = "/template/application_passed.template"
	ApplicationRejectedTemplateFilePath   = "/template/application_rejected.template"
	ApplicationProcessingTemplateFilePath = "/template/application_processing.template"
	TicketReplyTemplateFilePath           = "/template/ticket_reply.template"

	DefaultFilePermissions     = 0644
	DefaultDirectoryPermission = 0755

	FSDServerName      = "SERVER"
	ATISManagerName    = "ATIS_MANAGER"
	FSDDisconnectDelay = time.Second
)
