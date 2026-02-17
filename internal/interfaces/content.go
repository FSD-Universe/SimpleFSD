// Package interfaces
package interfaces

import (
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/interfaces/voice"
)

type ApplicationContent struct {
	configManager     ConfigManagerInterface
	cleaner           CleanerInterface
	clientManager     fsd.ClientManagerInterface
	connectionManager fsd.ConnectionManagerInterface
	logger            *log.Loggers
	messageQueue      queue.MessageQueueInterface
	metarManager      MetarManagerInterface
	operations        *operation.DatabaseOperations
	voiceServer       voice.ServerInterface
	tts               voice.TTSInterface
	transform         voice.ATISTransformerInterface
	generator         voice.ATISGeneratorInterface
}

func NewApplicationContent(
	logger *log.Loggers,
	cleaner CleanerInterface,
	configManager ConfigManagerInterface,
	clientManager fsd.ClientManagerInterface,
	connectionManager fsd.ConnectionManagerInterface,
	messageQueue queue.MessageQueueInterface,
	metarManager MetarManagerInterface,
	db *operation.DatabaseOperations,
	tts voice.TTSInterface,
	voiceServer voice.ServerInterface,
	transform voice.ATISTransformerInterface,
	generator voice.ATISGeneratorInterface,
) *ApplicationContent {
	return &ApplicationContent{
		configManager:     configManager,
		cleaner:           cleaner,
		clientManager:     clientManager,
		connectionManager: connectionManager,
		logger:            logger,
		messageQueue:      messageQueue,
		metarManager:      metarManager,
		operations:        db,
		tts:               tts,
		voiceServer:       voiceServer,
		transform:         transform,
		generator:         generator,
	}
}

func (app *ApplicationContent) ConfigManager() ConfigManagerInterface {
	return app.configManager
}

func (app *ApplicationContent) Cleaner() CleanerInterface { return app.cleaner }

func (app *ApplicationContent) ClientManager() fsd.ClientManagerInterface { return app.clientManager }

func (app *ApplicationContent) ConnectionManager() fsd.ConnectionManagerInterface {
	return app.connectionManager
}

func (app *ApplicationContent) Logger() *log.Loggers { return app.logger }

func (app *ApplicationContent) MessageQueue() queue.MessageQueueInterface { return app.messageQueue }

func (app *ApplicationContent) MetarManager() MetarManagerInterface { return app.metarManager }

func (app *ApplicationContent) Operations() *operation.DatabaseOperations { return app.operations }

func (app *ApplicationContent) TTS() voice.TTSInterface { return app.tts }

func (app *ApplicationContent) VoiceServer() voice.ServerInterface { return app.voiceServer }

func (app *ApplicationContent) Transform() voice.ATISTransformerInterface { return app.transform }

func (app *ApplicationContent) Generator() voice.ATISGeneratorInterface { return app.generator }

type ContentBuilder struct {
	content *ApplicationContent
}

func NewContentBuilder() *ContentBuilder {
	return &ContentBuilder{
		content: &ApplicationContent{},
	}
}

func (builder *ContentBuilder) SetConfigManager(configManager ConfigManagerInterface) *ContentBuilder {
	builder.content.configManager = configManager
	return builder
}

func (builder *ContentBuilder) SetCleaner(cleaner CleanerInterface) *ContentBuilder {
	builder.content.cleaner = cleaner
	return builder
}

func (builder *ContentBuilder) SetClientManager(clientManager fsd.ClientManagerInterface) *ContentBuilder {
	builder.content.clientManager = clientManager
	return builder
}

func (builder *ContentBuilder) SetConnectionManager(connectionManager fsd.ConnectionManagerInterface) *ContentBuilder {
	builder.content.connectionManager = connectionManager
	return builder
}

func (builder *ContentBuilder) SetLogger(logger *log.Loggers) *ContentBuilder {
	builder.content.logger = logger
	return builder
}

func (builder *ContentBuilder) SetMessageQueue(messageQueue queue.MessageQueueInterface) *ContentBuilder {
	builder.content.messageQueue = messageQueue
	return builder
}

func (builder *ContentBuilder) SetMetarManager(metarManager MetarManagerInterface) *ContentBuilder {
	builder.content.metarManager = metarManager
	return builder
}

func (builder *ContentBuilder) SetOperations(operations *operation.DatabaseOperations) *ContentBuilder {
	builder.content.operations = operations
	return builder
}

func (builder *ContentBuilder) SetTTS(tts voice.TTSInterface) *ContentBuilder {
	builder.content.tts = tts
	return builder
}

func (builder *ContentBuilder) SetVoiceServer(voiceServer voice.ServerInterface) *ContentBuilder {
	builder.content.voiceServer = voiceServer
	return builder
}

func (builder *ContentBuilder) SetTransform(transform voice.ATISTransformerInterface) *ContentBuilder {
	builder.content.transform = transform
	return builder
}

func (builder *ContentBuilder) SetGenerator(generator voice.ATISGeneratorInterface) *ContentBuilder {
	builder.content.generator = generator
	return builder
}

func (builder *ContentBuilder) Build() *ApplicationContent {
	return builder.content
}
