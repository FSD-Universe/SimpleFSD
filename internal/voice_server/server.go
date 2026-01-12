package voice_server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/voice"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type VoiceServer struct {
	logger      log.LoggerInterface
	tcpListener net.Listener
	udpConn     *net.UDPConn
	jwtSecret   []byte
	config      *config.VoiceServerConfig

	clientsMutex sync.RWMutex
	clients      map[int]*ClientInfo

	channelsMutex sync.RWMutex
	channels      map[ChannelFrequency]*Channel

	messageQueue      queue.MessageQueueInterface
	connectionManager fsd.ConnectionManagerInterface

	tcpLimiter       *utils.SlidingWindowLimiter
	udpLimiter       *utils.SlidingWindowLimiter
	addressSlicePool sync.Pool
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
}

func NewVoiceServer(
	application *interfaces.ApplicationContent,
) *VoiceServer {
	server := &VoiceServer{
		logger:            log.NewLoggerAdapter(application.Logger().VoiceLogger(), "VoiceServer"),
		jwtSecret:         []byte(application.ConfigManager().Config().Server.HttpServer.JWT.Secret),
		config:            application.ConfigManager().Config().Server.VoiceServer,
		clientsMutex:      sync.RWMutex{},
		clients:           make(map[int]*ClientInfo),
		channelsMutex:     sync.RWMutex{},
		channels:          make(map[ChannelFrequency]*Channel),
		messageQueue:      application.MessageQueue(),
		connectionManager: application.ConnectionManager(),
		addressSlicePool: sync.Pool{
			New: func() interface{} { return make([]*net.UDPAddr, 0, 128) },
		},
		wg: sync.WaitGroup{},
	}
	server.udpLimiter = utils.NewSlidingWindowLimiter(time.Minute, server.config.UDPPacketLimit)
	server.udpLimiter.StartCleanup(2 * time.Minute)
	server.tcpLimiter = utils.NewSlidingWindowLimiter(time.Minute, server.config.TCPPacketLimit)
	server.tcpLimiter.StartCleanup(2 * time.Minute)
	server.ctx, server.cancel = context.WithCancel(context.Background())
	application.Cleaner().Add(NewShutdownCallback(server))
	return server
}

func (s *VoiceServer) Start() error {
	tcpListener, err := net.Listen("tcp", s.config.TCPAddress)
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %v", err)
	}
	s.logger.InfoF("Voice server listening on tcp://%s", tcpListener.Addr())
	s.tcpListener = tcpListener

	udpAddr, err := net.ResolveUDPAddr("udp", s.config.UDPAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}
	s.logger.InfoF("Voice server listening on udp://%s", udpConn.LocalAddr())
	s.udpConn = udpConn

	s.wg.Add(2)
	go s.handleTCPConnections()
	go s.handleUDPConnections()

	return nil
}

func (s *VoiceServer) Stop() {
	s.logger.Debug("Stopping Voice Server")
	s.cancel()

	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}

	message := &ControlMessage{Type: Disconnect}
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()
	for _, client := range s.clients {
		go func(client *ClientInfo) {
			_ = client.SendControlMessage(message)
			time.AfterFunc(global.FSDDisconnectDelay, func() {
				_ = client.TCPConn.Close()
			})
		}(client)
	}

	s.wg.Wait()
}

func (s *VoiceServer) handleTCPConnections() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := s.tcpListener.Accept()
			if err != nil {
				s.logger.ErrorF("Failed to accept connection: %v", err)
				continue
			}
			s.logger.InfoF("Accepted new tcp connection from %s", conn.RemoteAddr())
			s.wg.Add(1)
			go s.handleTCPConnection(conn)
		}
	}
}

// TCP信令部分

func (s *VoiceServer) handleTCPConnection(conn net.Conn) {
	logger := log.NewLoggerAdapter(s.logger, fmt.Sprintf("tcp://%s", conn.RemoteAddr()))

	defer func(conn net.Conn) {
		logger.DebugF("Closing tcp connection")
		_ = conn.Close()
		s.wg.Done()
	}(conn)

	jwtToken, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		logger.ErrorF("Failed to read token: %v", err)
		return
	}

	jwtToken = strings.TrimRight(jwtToken, "\n")

	logger.DebugF("Jwt token received: %s", jwtToken)

	clientInfo, connection, err := s.authenticateClient(jwtToken)
	if err != nil {
		logger.ErrorF("Failed to authenticate client: %s", err.Error())
		s.sendError(conn, "Authentication failed: "+err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := NewClientInfo(logger, clientInfo.Cid, clientInfo.Callsign, conn, connection, cancel)

	defer s.cleanupClient(client)

	connection.SetDisconnectCallback(client.ConnectionDisconnect)

	s.clientsMutex.Lock()
	s.clients[clientInfo.Cid] = client
	s.clientsMutex.Unlock()
	if connection.IsAtc() {
		err = client.SendMessage(Message, fmt.Sprintf("SERVER:%s:Welcome:%d", client.Callsign, connection.Frequency()+100000))
	} else {
		err = client.SendMessage(Message, fmt.Sprintf("SERVER:%s:Welcome", client.Callsign))
	}
	if err != nil {
		logger.ErrorF("Failed to send message: %v", err)
		return
	}

	if err := s.setChannelController(connection, client); err != nil {
		logger.ErrorF("Failed to set channel controller: %v", err)
		_ = client.SendError(err.Error())
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.config.TimeoutDuration))
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ctx.Done():
			return
		default:
			msg := &ControlMessage{}
			if err := client.Decoder.Decode(msg); err != nil {
				if client.Disconnected.Load() {
					return
				}
				if errors.Is(err, io.EOF) {
					return
				}
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					logger.WarnF("Connection timeout: %s", conn.RemoteAddr())
					return
				}
				logger.ErrorF("Failed to decode message: %v", err)
				_ = client.SendError("Invalid message format")
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(s.config.TimeoutDuration))

			logger.DebugF("Received control message: %v", msg)

			if !s.tcpLimiter.Allow(client.TCPConn.RemoteAddr().String()) {
				_ = client.SendError("Packet limit reached")
				continue
			}

			if err := s.validateControlMessage(msg); err != nil {
				logger.ErrorF("Failed to validate control message: %s", err.Error())
				_ = client.SendError(err.Error())
				continue
			}

			s.handleControlMessage(client, msg)
		}
	}
}

func (s *VoiceServer) validateControlMessage(msg *ControlMessage) error {
	if msg.Cid == 0 {
		return errors.New("missing cid")
	}
	if len(msg.Data) > s.config.MaxDataSize {
		return errors.New("message too large")
	}
	return nil
}

func (s *VoiceServer) authenticateClient(tokenString string) (*ClientInfo, fsd.ClientInterface, error) {
	token, err := jwt.ParseWithClaims(tokenString, &service.Claims{}, func(token *jwt.Token) (interface{}, error) { return s.jwtSecret, nil })

	if err != nil || !token.Valid {
		return nil, nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*service.Claims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid token claims")
	}

	_, ok = s.clients[claims.Cid]
	if ok {
		return nil, nil, fmt.Errorf("client already login")
	}

	connections, err := s.connectionManager.GetConnections(claims.Cid)
	if err != nil {
		s.logger.ErrorF("error while getting connections: %v", err)
		if errors.Is(err, fsd.ErrCidNotFound) {
			return nil, nil, errors.New("no fsd connection found")
		}
		return nil, nil, errors.New("unknown server error")
	}

	connections = utils.Filter(connections, func(connection fsd.ClientInterface) bool {
		return !connection.IsAtc() || !connection.IsAtis()
	})

	if len(connections) > 1 {
		s.logger.ErrorF("too many fsd connections found, %d connections", len(connections))
		return nil, nil, errors.New("found more than one connection, please disconnect some of them until only one remains")
	}

	connection := connections[0]

	return &ClientInfo{
		Cid:      claims.Cid,
		Callsign: connection.Callsign(),
	}, connection, nil
}

func (s *VoiceServer) handleControlMessage(client *ClientInfo, msg *ControlMessage) {
	switch msg.Type {
	case Switch:
		s.handleChannelSwitch(client, msg)
	case Ping:
		s.handlePing(client, msg)
	case Message:
		s.handleTextMessage(client, msg)
	case Disconnect:
		s.handleDisconnect(client, msg)
	case TextReceive:
		if msg.Data == client.Callsign {
			client.Client.SetMessageReceivedCallback(client.MessageReceive)
		} else {
			client.Client.SetMessageReceivedCallback(nil)
		}
	case VoiceReceive:
		s.handleVoiceReceive(client, msg)
	default:
		if err := client.SendError("Unknown message type"); err != nil {
			s.logger.ErrorF("Failed to send message: %v", err)
			return
		}
	}
}

func (s *VoiceServer) handleVoiceReceive(client *ClientInfo, msg *ControlMessage) {
	frequencyStr, receiveFlagStr, success := strings.Cut(msg.Data, ":")
	if !success {
		client.Logger.ErrorF("Fail to handle VoiceReceive packet, data format error: %s", msg.Data)
		_ = client.SendError(fmt.Sprintf("Invalid data format of %s", msg.Data))
		return
	}

	frequency := utils.StrToInt(frequencyStr, -1)
	if frequency == -1 {
		client.Logger.ErrorF("Fail to handle VoiceReceive packet, invalid frequency: %s", frequencyStr)
		_ = client.SendError(fmt.Sprintf("Invalid frequency of %s", frequencyStr))
		return
	}

	transmitter := s.getOrCreateTransmitter(client, msg.Transmitter)
	freq := ChannelFrequency(frequency)
	if freq != transmitter.Frequency {
		client.Logger.ErrorF("Fail to handle VoiceReceive packet, frequency mismatch, expect %d got %d", transmitter.Frequency, freq)
		_ = client.SendError(fmt.Sprintf("Frequency %s mismatch stored frequency of transmitter %d", frequencyStr, msg.Transmitter))
		return
	}

	transmitter.ReceiveFlag = receiveFlagStr == "1"

	_ = client.SendMessage(Message, fmt.Sprintf("SERVER:Transmitter %d set receive flag: %s", msg.Transmitter, strconv.FormatBool(transmitter.ReceiveFlag)))
}

func (s *VoiceServer) handleChannelSwitch(client *ClientInfo, msg *ControlMessage) {
	frequencyStr, receiveFlagStr, success := strings.Cut(msg.Data, ":")
	if !success {
		client.Logger.ErrorF("Fail to handle ChannelSwitch packet, data format error: %s", msg.Data)
		_ = client.SendError(fmt.Sprintf("Invalid data format of %s", msg.Data))
		return
	}

	frequency := utils.StrToInt(frequencyStr, -1)
	if frequency == -1 {
		client.Logger.ErrorF("Fail to handle ChannelSwitch packet, invalid frequency: %s", frequencyStr)
		_ = client.SendError(fmt.Sprintf("Invalid frequency of %s", frequencyStr))
		return
	}

	freq := ChannelFrequency(frequency)
	transmitter := s.getOrCreateTransmitter(client, msg.Transmitter)

	s.removeFromChannel(transmitter)

	transmitter.Frequency = freq
	transmitter.ReceiveFlag = receiveFlagStr == "1"

	s.addToChannel(transmitter)

	message := fmt.Sprintf("Transmitter %d switched to %d, receive: %s", msg.Transmitter, freq, strconv.FormatBool(transmitter.ReceiveFlag))
	client.Logger.Debug(message)
	_ = client.SendMessage(Message, "SERVER:"+message)
}

func (s *VoiceServer) handlePing(client *ClientInfo, msg *ControlMessage) {
	_ = client.SendControlMessage(&ControlMessage{
		Type:     Pong,
		Cid:      client.Cid,
		Callsign: client.Callsign,
		Data:     msg.Data,
	})
}

func (s *VoiceServer) handleTextMessage(client *ClientInfo, msg *ControlMessage) {
	to, message, found := strings.Cut(msg.Data, ":")
	if !found {
		client.Logger.ErrorF("Fail to handle TextMessage packet, data format error: %s", msg.Data)
		_ = client.SendError(fmt.Sprintf("Invalid data format of %s", msg.Data))
		return
	}

	client.Logger.DebugF("Received message from client: %s", msg.Data)

	if fsd.IsValidBroadcastTarget(to) {
		s.messageQueue.Publish(&queue.Message{
			Type: queue.BroadcastMessage,
			Data: &fsd.BroadcastMessageData{
				From:    client.Callsign,
				Target:  fsd.BroadcastTarget(to),
				Message: message,
			},
		})
	} else {
		s.messageQueue.Publish(&queue.Message{
			Type: queue.SendMessageToClient,
			Data: &fsd.SendRawMessageData{
				From:    client.Callsign,
				To:      to,
				Message: message,
			},
		})
	}
}

func (s *VoiceServer) handleDisconnect(client *ClientInfo, _ *ControlMessage) {
	s.cleanupClient(client)
	_ = client.SendControlMessage(&ControlMessage{Type: Disconnect})
	time.AfterFunc(global.FSDDisconnectDelay, func() {
		_ = client.TCPConn.Close()
	})
}

// UDP语音数据

func (s *VoiceServer) handleUDPConnections() {
	defer s.wg.Done()
	buffer := make([]byte, 65507)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			n, addr, err := s.udpConn.ReadFromUDP(buffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.ErrorF("Error reading from UDP: %v", err)
				continue
			}

			if !s.udpLimiter.Allow(addr.String()) {
				s.logger.WarnF("Drop UDP data due to rate limit exceeded for %s", addr)
				continue
			}

			if n == 0 {
				s.logger.DebugF("Zero packet received from udp://%s", addr)
				continue
			}

			if n > 65507 {
				s.logger.WarnF("Oversized UDP packet from udp://%s", addr)
				continue
			}

			if !bytes.HasSuffix(buffer[:n], []byte("\n")) {
				s.logger.WarnF("Receive incomplete voice data from udp://%s", addr)
				continue
			}

			data := buffer[:n-1]

			if len(data) < 9 {
				s.logger.WarnF("Packet too short from udp://%s: %d bytes", addr, len(data))
				continue
			}

			reader := bytes.NewReader(data)

			var cid int32
			if err := binary.Read(reader, binary.LittleEndian, &cid); err != nil {
				s.logger.WarnF("Failed to read CID from udp://%s: %v", addr, err)
				continue
			}

			var transmitter int8
			if err := binary.Read(reader, binary.LittleEndian, &transmitter); err != nil {
				s.logger.WarnF("Failed to read Transmitter from udp://%s: %v", addr, err)
				continue
			}

			var frequency int32
			if err := binary.Read(reader, binary.LittleEndian, &frequency); err != nil {
				s.logger.WarnF("Failed to read Frequency from udp://%s: %v", addr, err)
				continue
			}

			callsignStart := 9
			callsignLength := int8(data[callsignStart])
			if callsignLength < 0 {
				s.logger.WarnF("Invalid callsign length from udp://%s: %d", addr, callsignLength)
				continue
			}
			callsignEnd := callsignStart + 1 + int(callsignLength)

			if n-1 < callsignEnd {
				s.logger.WarnF("Not enough data for callsign from udp://%s: need %d, have %d",
					addr, callsignEnd, len(data))
				continue
			}

			callsign := string(data[callsignStart+1 : callsignEnd])
			audioData := data[callsignEnd:]

			if cid <= 0 || frequency <= 0 || transmitter < 0 {
				s.logger.WarnF("Invalid voice packet fields from %s: CID=%d, Frequency=%d, Transmitter=%d", addr, cid, frequency, transmitter)
				continue
			}

			voicePacket := &VoicePacket{
				Cid:         int(cid),
				Transmitter: int(transmitter),
				Frequency:   int(frequency) + 100000,
				Callsign:    callsign,
				Data:        audioData,
			}

			s.broadcastVoicePacket(voicePacket, addr, buffer[:n])
		}
	}
}

func (s *VoiceServer) handleUpdateUDPAddress(packet *VoicePacket, addr *net.UDPAddr) (*ClientInfo, *Transmitter) {
	s.clientsMutex.RLock()
	client, ok := s.clients[packet.Cid]
	s.clientsMutex.RUnlock()

	if !ok {
		s.logger.DebugF("Client %d not found", packet.Cid)
		return nil, nil
	}

	transmitter := s.getOrCreateTransmitter(client, packet.Transmitter)
	transmitter.UDPAddr = addr
	return client, transmitter
}

func (s *VoiceServer) broadcastVoicePacket(packet *VoicePacket, fromAddr *net.UDPAddr, rawData []byte) {
	client, transmitter := s.handleUpdateUDPAddress(packet, fromAddr)
	if client == nil || transmitter == nil {
		return
	}

	if len(packet.Data) == 0 {
		return
	}

	if client.Callsign != packet.Callsign {
		client.Logger.WarnF("Invalid callsign from %s, expected %s, got %s", fromAddr, client.Callsign, packet.Callsign)
		return
	}

	if int(transmitter.Frequency) != packet.Frequency {
		client.Logger.WarnF("frequency mismatch, drop UDP packet, expected %d, got %d", packet.Frequency, transmitter.Frequency)
		return
	}

	s.channelsMutex.RLock()
	channel, exists := s.channels[transmitter.Frequency]
	s.channelsMutex.RUnlock()

	if !exists {
		client.Logger.ErrorF("Channel %d not found from %s", transmitter.Frequency, client.Callsign)
		return
	}

	targets := s.addressSlicePool.Get().([]*net.UDPAddr)
	targets = targets[:0]
	defer s.addressSlicePool.Put(targets)

	channel.ClientsMutex.RLock()
	for _, clientTransmitter := range channel.Clients {
		if clientTransmitter.UDPAddr == nil {
			continue
		}
		if clientTransmitter.UDPAddr.String() == transmitter.UDPAddr.String() {
			continue
		}
		if !clientTransmitter.ReceiveFlag {
			continue
		}
		// 如果管制员在线且是机组发往机组
		if channel.Controller != nil && !clientTransmitter.ClientInfo.Client.IsAtc() && !transmitter.ClientInfo.Client.IsAtc() {
			targets = append(targets, clientTransmitter.UDPAddr)
			continue
		}
		if fsd.BroadcastToClientInRangeWithVoiceRange(clientTransmitter.ClientInfo.Client, client.Client) {
			targets = append(targets, clientTransmitter.UDPAddr)
		}
	}
	channel.ClientsMutex.RUnlock()

	if len(targets) == 0 {
		return
	}

	s.broadcastToTargets(targets, rawData, client)
}

// 工具函数

func (s *VoiceServer) sendError(conn net.Conn, msg string) {
	s.sendMessage(conn, Error, msg)
}

func (s *VoiceServer) sendMessage(conn net.Conn, messageType MessageType, msg string) {
	message := &ControlMessage{
		Type: messageType,
		Data: msg,
	}
	s.sendControlMessage(conn, message)
}

func (s *VoiceServer) sendControlMessage(conn net.Conn, msg *ControlMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		s.logger.ErrorF("failed to marshal control message: %v", err)
	}

	_, err = conn.Write(data)
	if err != nil {
		s.logger.ErrorF("failed to write control message: %v", err)
	}
}

func (s *VoiceServer) cleanupClient(client *ClientInfo) {
	if client.Disconnected.Load() {
		return
	}

	for _, transmitter := range client.Transmitters {
		s.removeFromChannel(transmitter)
	}

	s.clientsMutex.Lock()
	delete(s.clients, client.Cid)
	s.clientsMutex.Unlock()

	client.Disconnected.Store(true)
}

// 频道管理

func (s *VoiceServer) getOrCreateTransmitter(client *ClientInfo, transmitterID int) *Transmitter {
	client.TransmitterMutex.Lock()
	defer client.TransmitterMutex.Unlock()

	for len(client.Transmitters) < transmitterID+1 {
		client.Transmitters = append(client.Transmitters, &Transmitter{
			Id:          len(client.Transmitters),
			ClientInfo:  client,
			Frequency:   0,
			ReceiveFlag: false,
			UDPAddr:     nil,
		})
	}

	return client.Transmitters[transmitterID]
}

func (s *VoiceServer) addToChannel(transmitter *Transmitter) {
	s.channelsMutex.Lock()
	defer s.channelsMutex.Unlock()

	channel := s.getOrCreateChannel(transmitter.Frequency)

	channel.ClientsMutex.Lock()
	channel.Clients[transmitter.ClientInfo.Cid] = transmitter
	channel.ClientsMutex.Unlock()
}

func (s *VoiceServer) getOrCreateChannel(frequency ChannelFrequency) *Channel {
	s.channelsMutex.Lock()
	defer s.channelsMutex.Unlock()

	channel, exists := s.channels[frequency]
	if !exists {
		channel = &Channel{
			Frequency:    frequency,
			ClientsMutex: sync.RWMutex{},
			Clients:      make(map[int]*Transmitter),
			CreatedAt:    time.Now(),
		}
		s.channels[frequency] = channel
	}

	return channel
}

func (s *VoiceServer) removeFromChannel(transmitter *Transmitter) {
	s.channelsMutex.Lock()
	defer s.channelsMutex.Unlock()

	channel, exists := s.channels[transmitter.Frequency]
	if !exists {
		return
	}

	if channel.Controller.Callsign() == transmitter.ClientInfo.Client.Callsign() {
		channel.Controller = nil
	}

	channel.ClientsMutex.Lock()
	delete(channel.Clients, transmitter.ClientInfo.Cid)
	channel.ClientsMutex.Unlock()

	if len(channel.Clients) == 0 && channel.Controller == nil {
		delete(s.channels, channel.Frequency)
	}
}

func (s *VoiceServer) setChannelController(connection fsd.ClientInterface, client *ClientInfo) error {
	if !connection.IsAtc() || connection.IsAtis() {
		return nil
	}
	freq := ChannelFrequency(connection.Frequency() + 100000)
	if freq == UNICOM || freq == EMERGENCY {
		return fmt.Errorf("cannot use unicom or emergency frequency as main frequency")
	}
	c := s.getOrCreateChannel(freq)
	if c.Controller != nil {
		return fmt.Errorf("channel %d already has a controller", freq)
	}
	s.logger.InfoF("Setting channel %d controller to %s(%04d)", freq, client.Callsign, client.Cid)
	c.Controller = client.Client
	return nil
}
