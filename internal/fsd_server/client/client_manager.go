package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type ClientManager struct {
	logger            log.LoggerInterface
	clients           map[string]ClientInterface
	connectionManager ConnectionManagerInterface
	lock              sync.RWMutex
	shuttingDown      atomic.Bool
	config            *config.Config
	clientSlicePool   sync.Pool
	messageQueue      queue.MessageQueueInterface
	whazzupContent    *utils.CachedValue[*OnlineClients]
}

func NewClientManager(
	logger log.LoggerInterface,
	config *config.Config,
	connectionManager ConnectionManagerInterface,
	messageQueue queue.MessageQueueInterface,
) *ClientManager {
	clientManager := &ClientManager{
		logger:            log.NewLoggerAdapter(logger, "ClientManager"),
		clients:           make(map[string]ClientInterface),
		shuttingDown:      atomic.Bool{},
		config:            config,
		connectionManager: connectionManager,
		messageQueue:      messageQueue,
		clientSlicePool: sync.Pool{
			New: func() interface{} {
				return make([]ClientInterface, 0, 128)
			},
		},
	}
	clientManager.whazzupContent = utils.NewCachedValue(config.Server.FSDServer.CacheDuration, func() *OnlineClients { return clientManager.getWhazzupContent() })
	return clientManager
}

func (cm *ClientManager) sendRawMessageTo(from string, to string, message string) error {
	client, exists := cm.GetClient(to)
	if !exists {
		return ErrCallsignNotFound
	}

	packet := MakePacket(Message, from, to, message)

	client.SendLine(packet)
	return nil
}

func (cm *ClientManager) HandleLockChangeMessage(message *queue.Message) error {
	if val, ok := message.Data.(*LockChange); ok {
		client, ok := cm.GetClient(val.TargetCallsign)
		if !ok {
			return ErrCallsignNotFound
		}
		if client.User().Cid != val.TargetCid {
			return ErrCidMissMatch
		}
		client.FlightPlan().Locked = val.Locked
	}
	return queue.ErrMessageDataType
}

func (cm *ClientManager) HandleFlightPlanFlushMessage(message *queue.Message) error {
	if val, ok := message.Data.(*FlushFlightPlan); ok {
		client, ok := cm.GetClient(val.TargetCallsign)
		if !ok {
			return ErrCallsignNotFound
		}
		if client.User().Cid != val.TargetCid {
			return ErrCidMissMatch
		}
		if val.FlightPlan == nil {
			client.ClearFlightPlan()
		} else {
			client.SetFlightPlan(val.FlightPlan)
		}
		return nil
	}
	return queue.ErrMessageDataType
}

func (cm *ClientManager) HandleSendMessageToClientMessage(message *queue.Message) error {
	if val, ok := message.Data.(*SendRawMessageData); ok {
		return cm.sendRawMessageTo(val.From, val.To, val.Message)
	}
	return queue.ErrMessageDataType
}

func (cm *ClientManager) broadcastMessage(message *BroadcastMessageData) error {
	if cm.shuttingDown.Load() {
		return errors.New("client manager shutting down")
	}

	if len(message.Message) == 0 {
		return errors.New("message is empty")
	}

	clients := cm.GetClientSnapshot()
	defer cm.putSlice(clients)

	if len(clients) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, cm.config.Server.FSDServer.MaxBroadcastWorkers)

	var filter ClientFilter

	switch message.Target {
	case AllSup:
		filter = BroadcastToSupClient
	case AllATC:
		message.Target = AllClient
		filter = BroadcastToATCClient
	case AllPilot:
		message.Target = AllClient
		filter = BroadcastToAllPilotClient
	case AllClient:
		filter = BroadcastToAllClient
	}

	packet := MakePacket(Message, message.From, message.Target.String(), message.Message)

	for _, client := range clients {
		if client.Disconnected() {
			continue
		}

		if filter != nil && !filter(client) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(cl ClientInterface) {
			defer func() {
				<-sem
				wg.Done()
			}()

			cm.logger.DebugF("[Broadcast] -> [%s] %s", cl.Callsign(), string(bytes.TrimRight(packet, "\r\n")))
			err := cl.SendLineWithoutLog(packet)
			if err != nil && errors.Is(err, ErrClientSocketWrite) {
				cl.MarkedDisconnect(false)
			}
		}(client)
	}

	wg.Wait()
	return nil
}

func (cm *ClientManager) HandleBroadcastMessage(message *queue.Message) error {
	if val, ok := message.Data.(*BroadcastMessageData); ok {
		return cm.broadcastMessage(val)
	}
	return queue.ErrMessageDataType
}

func (cm *ClientManager) KickClientFromServer(callsign string, reason string) (ClientInterface, error) {
	client, exists := cm.GetClient(callsign)
	if !exists {
		return nil, ErrCallsignNotFound
	}
	client.SendError(ResultError(Custom, true, callsign, fmt.Errorf("you were kicked from the server, reason is %s", reason)))
	return client, nil
}

func (cm *ClientManager) HandleKickClientFromServerMessage(message *queue.Message) error {
	if val, ok := message.Data.(*KickClientData); ok {
		_, err := cm.KickClientFromServer(val.Callsign, val.Reason)
		return err
	}
	return queue.ErrMessageDataType
}

func (cm *ClientManager) GetWhazzupCacheTime() time.Duration {
	return cm.config.Server.FSDServer.CacheDuration
}

func (cm *ClientManager) GetWhazzupContent() *OnlineClients {
	return cm.whazzupContent.GetValue()
}

func (cm *ClientManager) getWhazzupContent() *OnlineClients {
	data := &OnlineClients{
		General: OnlineGeneral{
			Version:          3,
			ConnectedClients: 0,
			OnlinePilot:      0,
			OnlineController: 0,
		},
	}

	clientCopy := cm.GetClientSnapshot()
	defer cm.putSlice(clientCopy)

	clientCopy = utils.Filter(clientCopy, func(client ClientInterface) bool {
		return client != nil && !client.Disconnected()
	})

	data.General.ConnectedClients = len(clientCopy)

	controllers := utils.Filter(clientCopy, func(client ClientInterface) bool { return client.IsAtc() })
	data.General.OnlineController = len(controllers)
	data.Controllers = utils.Map(controllers, func(client ClientInterface) *OnlineController { return NewOnlineControllerFromClient(client) })

	pilots := utils.Filter(clientCopy, func(client ClientInterface) bool { return !client.IsAtc() })
	data.General.OnlinePilot = len(pilots)
	data.Pilots = utils.Map(pilots, func(client ClientInterface) *OnlinePilot { return NewOnlinePilotFromClient(client) })

	data.General.GenerateTime = time.Now().Format(time.RFC3339)

	return data
}

func (cm *ClientManager) putSlice(clients []ClientInterface) {
	cm.clientSlicePool.Put(clients)
}

func (cm *ClientManager) Shutdown(ctx context.Context) error {
	if !cm.shuttingDown.CompareAndSwap(false, true) {
		return fmt.Errorf("shutting down already in progress")
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	clients := cm.GetClientSnapshot()
	defer cm.putSlice(clients)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cm.disconnectClients(clients)
	}()

	select {
	case <-done:
		return nil
	case <-timeoutCtx.Done():
		return timeoutCtx.Err()
	}
}

func (cm *ClientManager) GetClientSnapshot() []ClientInterface {
	cm.lock.RLock()
	defer cm.lock.RUnlock()

	// 从池中获取切片
	clients := cm.clientSlicePool.Get().([]ClientInterface)
	clients = clients[:0]

	// 填充客户端
	for _, client := range cm.clients {
		clients = append(clients, client)
	}
	return clients
}

func (cm *ClientManager) disconnectClients(clients []ClientInterface) {
	if len(clients) == 0 {
		return
	}

	sem := make(chan struct{}, cm.config.Server.FSDServer.MaxBroadcastWorkers)
	var wg sync.WaitGroup

	for _, client := range clients {
		wg.Add(1)
		sem <- struct{}{}

		go func(c ClientInterface) {
			defer func() {
				<-sem
				wg.Done()
			}()

			c.MarkedDisconnect(true)
		}(client)
	}

	wg.Wait()
}

func (cm *ClientManager) AddClient(client ClientInterface) error {
	if cm.shuttingDown.Load() {
		return fmt.Errorf("server shutting down")
	}
	cm.lock.Lock()
	defer cm.lock.Unlock()

	if _, exists := cm.clients[client.Callsign()]; exists {
		return fmt.Errorf("client already registered: %s", client.Callsign())
	}
	cm.clients[client.Callsign()] = client
	cm.connectionManager.AddConnection(client)
	return nil
}

func (cm *ClientManager) GetClient(callsign string) (ClientInterface, bool) {
	if cm.shuttingDown.Load() {
		return nil, false
	}

	cm.lock.RLock()
	defer cm.lock.RUnlock()

	client, exists := cm.clients[callsign]
	return client, exists
}

func (cm *ClientManager) DeleteClient(callsign string) error {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	client, exists := cm.clients[callsign]
	if !exists {
		return nil
	}

	delete(cm.clients, callsign)
	return cm.connectionManager.RemoveConnection(client)
}

func (cm *ClientManager) SendMessageTo(callsign string, message []byte) error {
	if cm.shuttingDown.Load() {
		return errors.New("server is shutting down")
	}

	if strings.HasPrefix(callsign, cm.config.Server.HttpServer.ClientPrefix) &&
		strings.HasSuffix(callsign, cm.config.Server.HttpServer.ClientSuffix) {
		cm.messageQueue.Publish(&queue.Message{
			Type: queue.FsdMessageReceived,
			Data: message,
		})
	} else {
		client, exists := cm.GetClient(callsign)
		if !exists {
			return ErrCallsignNotFound
		}
		client.SendLine(message)
	}

	return nil
}

func (cm *ClientManager) BroadcastMessage(message []byte, fromClient ClientInterface, filter BroadcastFilter) {
	if cm.shuttingDown.Load() || len(message) == 0 {
		return
	}

	clients := cm.GetClientSnapshot()
	defer cm.putSlice(clients) // 重置并放回池中

	if len(clients) == 0 {
		return
	}

	messageLen := len(message)
	fullMsg := make([]byte, messageLen)
	copy(fullMsg, message)
	if !bytes.HasSuffix(message, SplitSign) {
		fullMsg = append(fullMsg, SplitSign...)
	}

	// 并发广播
	var wg sync.WaitGroup
	sem := make(chan struct{}, cm.config.Server.FSDServer.MaxBroadcastWorkers)

	for _, client := range clients {
		if client == fromClient || client.Disconnected() {
			continue
		}

		if filter != nil && !filter(client, fromClient) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(cl ClientInterface) {
			defer func() {
				<-sem
				wg.Done()
			}()

			cm.logger.DebugF("[Broadcast] -> [%s] %s", cl.Callsign(), fullMsg[:messageLen])
			err := cl.SendLineWithoutLog(fullMsg)
			if err != nil && errors.Is(err, ErrClientSocketWrite) {
				cl.MarkedDisconnect(false)
			}
		}(client)
	}

	wg.Wait()
}
