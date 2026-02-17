// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	tcpLimiter *utils.SlidingWindowLimiter
	udpLimiter *utils.SlidingWindowLimiter

	// 缓存池
	addressSlicePool            sync.Pool
	addrMapPool                 sync.Pool
	clientInterfaceSlicePool    sync.Pool
	clientInfoSlicePool         sync.Pool
	broadcastCandidateSlicePool sync.Pool
	voicePacketPool             sync.Pool
	voiceDataPool               sync.Pool
	bytePool                    sync.Pool

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	tts         TTSInterface
	transform   ATISTransformerInterface
	generator   ATISGeneratorInterface
	opusEncoder *OpusEncoder
	atisMutex   sync.RWMutex
	atisInfos   map[string]*ATISClientInfo
}

type ATISClientInfo struct {
	Cid              int
	Callsign         string
	ClientInfo       *ClientInfo
	Frequency        int
	Transmitter      *Transmitter
	VoiceFrames      [][]byte
	VoiceFramesMutex sync.RWMutex
	VoiceFramesIndex atomic.Uint32
	CancelFunc       context.CancelFunc
}

type broadcastCandidate struct {
	client fsd.ClientInterface
	addr   *net.UDPAddr
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
			New: func() interface{} { return make([]*net.UDPAddr, 0, *global.VoicePoolSize) },
		},
		addrMapPool: sync.Pool{
			New: func() interface{} { return make(map[string]*net.UDPAddr) },
		},
		clientInterfaceSlicePool: sync.Pool{
			New: func() interface{} { return make([]fsd.ClientInterface, 0, 16) },
		},
		clientInfoSlicePool: sync.Pool{
			New: func() interface{} { return make([]*ClientInfo, 0, 16) },
		},
		broadcastCandidateSlicePool: sync.Pool{
			New: func() interface{} { return make([]broadcastCandidate, 0, *global.VoicePoolSize) },
		},
		voicePacketPool: sync.Pool{
			New: func() interface{} { return NewVoicePacket() },
		},
		voiceDataPool: sync.Pool{
			New: func() interface{} { return make([]byte, *global.VoicePoolSize) },
		},
		bytePool: sync.Pool{
			New: func() interface{} { return make([]byte, 1<<12) },
		},
		wg:        sync.WaitGroup{},
		tts:       application.TTS(),
		transform: application.Transform(),
		generator: application.Generator(),
		atisMutex: sync.RWMutex{},
		atisInfos: make(map[string]*ATISClientInfo),
	}
	if server.config.EnableATISVoice {
		server.opusEncoder = NewOpusEncoder(server.config)
	}
	server.udpLimiter = utils.NewSlidingWindowLimiter(time.Minute, server.config.UDPPacketLimit)
	server.udpLimiter.StartCleanup(2 * time.Minute)
	server.tcpLimiter = utils.NewSlidingWindowLimiter(time.Minute, server.config.TCPPacketLimit)
	server.tcpLimiter.StartCleanup(2 * time.Minute)
	server.ctx, server.cancel = context.WithCancel(context.Background())
	application.Cleaner().Add(NewShutdownCallback(server))
	return server
}

func (s *VoiceServer) ATISUpdate(client fsd.ClientInterface) {
	if !s.config.EnableATISVoice {
		return
	}
	callsign := client.Callsign()
	s.atisMutex.RLock()
	atisInfo, ok := s.atisInfos[callsign]
	s.atisMutex.RUnlock()
	if !ok {
		atisInfo = &ATISClientInfo{
			Cid:      client.User().Cid,
			Callsign: callsign,
			ClientInfo: &ClientInfo{
				Cid:      client.User().Cid,
				Callsign: client.Callsign(),
				Client:   client,
				Logger:   log.NewLoggerAdapter(s.logger, client.Callsign()),
			},
			Frequency: client.Frequency() + 100000,
		}
		atisInfo.Transmitter = &Transmitter{
			Id:          0,
			ClientInfo:  atisInfo.ClientInfo,
			Frequency:   ChannelFrequency(atisInfo.Frequency),
			ReceiveFlag: false,
		}
		s.atisMutex.Lock()
		s.atisInfos[callsign] = atisInfo
		s.atisMutex.Unlock()
		s.addToChannel(atisInfo.Transmitter)
	}
	if atisInfo.CancelFunc != nil {
		atisInfo.ClientInfo.Logger.DebugF("Cancel ATIS playback: %s", callsign)
		atisInfo.CancelFunc()
		atisInfo.CancelFunc = nil
	}
	rawAtisInfo := strings.Join(client.AtisInfo(), " ")
	atisRaw := s.transform.Transform(rawAtisInfo)
	generatedText := s.generator.Generate(atisRaw)
	atisInfo.ClientInfo.Logger.DebugF("Generated text: %s", generatedText)
	voiceData, err := s.tts.Synthesize(generatedText)
	if err != nil {
		s.logger.ErrorF("Failed to synthesize ATIS voice data: %v", err)
		return
	}
	atisInfo.ClientInfo.Logger.DebugF("Voice data length: %d", len(voiceData))
	data, err := s.opusEncoder.EncodePCM(voiceData)
	if err != nil {
		s.logger.ErrorF("Failed to encode ATIS voice data: %v", err)
		return
	}
	atisInfo.ClientInfo.Logger.DebugF("Opus data length: %d", len(data))
	for i, datum := range data {
		data[i] = s.buildAtisVoicePacket(int32(atisInfo.Cid), 0, int32(atisInfo.Frequency), atisInfo.Callsign, datum)
	}
	atisInfo.VoiceFramesMutex.Lock()
	atisInfo.VoiceFrames = data
	atisInfo.VoiceFramesIndex.Store(0)
	atisInfo.VoiceFramesMutex.Unlock()
	go s.startAtisVoice(atisInfo)
}

func (s *VoiceServer) ATISOffline(client fsd.ClientInterface) {
	s.logger.InfoF("ATIS offline: %s", client.Callsign())
	callsign := client.Callsign()
	s.atisMutex.RLock()
	atisInfo, ok := s.atisInfos[callsign]
	s.atisMutex.RUnlock()
	if !ok {
		return
	}
	if atisInfo.CancelFunc != nil {
		s.logger.DebugF("Cancel ATIS playback: %s", callsign)
		atisInfo.CancelFunc()
		atisInfo.CancelFunc = nil
	}
	atisInfo.VoiceFramesMutex.Lock()
	atisInfo.VoiceFrames = nil
	atisInfo.VoiceFramesMutex.Unlock()
	s.atisMutex.Lock()
	delete(s.atisInfos, callsign)
	s.atisMutex.Unlock()
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

	s.atisMutex.Lock()
	defer s.atisMutex.Unlock()
	for _, atisInfo := range s.atisInfos {
		if atisInfo.CancelFunc != nil {
			atisInfo.CancelFunc()
			atisInfo.CancelFunc = nil
		}
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
		if r := recover(); r != nil {
			buf := s.bytePool.Get().([]byte)
			stackSize := runtime.Stack(buf, false)
			logger.ErrorF("Recovered from panic: %v", r)
			logger.ErrorF("Stack trace: %s", buf[:stackSize])
			s.bytePool.Put(buf)
		}
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

	go s.handleClientPacket(ctx, client)

	connection.SetAudioOnline(true)

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

			logger.DebugF("Received control message: %#v", msg)

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
	if msg.Cid <= 0 {
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
	if err != nil || connections == nil || len(connections) == 0 {
		s.logger.ErrorF("error while getting connections: %v", err)
		if errors.Is(err, fsd.ErrCidNotFound) {
			return nil, nil, errors.New("no fsd connection found")
		}
		return nil, nil, errors.New("unknown server error")
	}

	connections = utils.Filter(connections, func(connection fsd.ClientInterface) bool {
		return !connection.Disconnected() && (!connection.IsAtc() || !connection.IsAtis())
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

	if !client.Client.IsAtc() {
		if transmitter.Id == 0 {
			client.Client.SetAudioCOM1(frequency, transmitter.ReceiveFlag)
		} else if transmitter.Id == 1 {
			client.Client.SetAudioCOM2(frequency, transmitter.ReceiveFlag)
		}
	}

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

	if !client.Client.IsAtc() {
		if transmitter.Id == 0 {
			client.Client.SetAudioCOM1(frequency, transmitter.ReceiveFlag)
		} else if transmitter.Id == 1 {
			client.Client.SetAudioCOM2(frequency, transmitter.ReceiveFlag)
		}
	}

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

			if len(audioData) != 0 && (cid < 0 || frequency <= 0 || transmitter < 0) {
				s.logger.WarnF("Invalid voice packet fields from %s: CID=%d, Frequency=%d, Transmitter=%d", addr, cid, frequency, transmitter)
				continue
			}

			voicePacket := s.voicePacketPool.Get().(*VoicePacket)

			if n <= *global.VoicePoolSize {
				voicePacket.RawData = s.voiceDataPool.Get().([]byte)[:n]
				voicePacket.Data = s.voiceDataPool.Get().([]byte)[:len(audioData)]
			} else {
				voicePacket.RawData = make([]byte, n)
				voicePacket.Data = make([]byte, len(audioData))
			}
			copy(voicePacket.RawData, buffer[:n])
			copy(voicePacket.Data, audioData)

			voicePacket.Cid = int(cid)
			voicePacket.Transmitter = int(transmitter)
			voicePacket.Frequency = int(frequency)
			voicePacket.Callsign = callsign

			client := s.handleUpdateUDPAddress(voicePacket, addr)
			if client == nil {
				s.recycleVoicePacket(voicePacket)
				continue
			}
			if len(audioData) == 0 {
				s.recycleVoicePacket(voicePacket)
				continue
			}
			select {
			case client.Channel <- voicePacket:
			default:
				s.recycleVoicePacket(voicePacket)
				s.logger.WarnF("Voice packet dropped for client %d", client.Cid)
			}
		}
	}
}

func (s *VoiceServer) handleUpdateUDPAddress(packet *VoicePacket, addr *net.UDPAddr) *ClientInfo {
	s.clientsMutex.RLock()
	client, ok := s.clients[packet.Cid]
	s.clientsMutex.RUnlock()

	if !ok {
		s.logger.WarnF("Client %d not found", packet.Cid)
		return nil
	}

	client.UDPAddr = addr
	return client
}

func (s *VoiceServer) handleBroadcast(client *ClientInfo, packet *VoicePacket) {
	defer s.recycleVoicePacket(packet)
	transmitter := s.getOrCreateTransmitter(client, packet.Transmitter)
	if transmitter == nil {
		client.Logger.WarnF("Client %d not found", packet.Cid)
		return
	}

	if client.Callsign != packet.Callsign {
		client.Logger.WarnF("Invalid callsign from %s, expected %s, got %s", client.UDPAddr, client.Callsign, packet.Callsign)
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
	targets := s.addressSlicePool.Get().([]*net.UDPAddr)[:0]
	defer s.addressSlicePool.Put(targets)

	channel.ClientsMutex.RLock()
	n := len(channel.Clients)
	needCtrl := len(channel.Controllers)
	controllers := s.clientInterfaceSlicePool.Get().([]fsd.ClientInterface)
	controllersFromPool := true
	if cap(controllers) < needCtrl {
		controllers = make([]fsd.ClientInterface, needCtrl)
		controllersFromPool = false
	} else {
		controllers = controllers[:needCtrl]
	}
	copy(controllers, channel.Controllers)
	candidates := s.broadcastCandidateSlicePool.Get().([]broadcastCandidate)[:0]
	candidatesFromPool := true
	if cap(candidates) < n {
		candidates = make([]broadcastCandidate, 0, n)
		candidatesFromPool = false
	}
	for _, ct := range channel.Clients {
		// 排除没有注册地址的客户端
		if ct.ClientInfo.UDPAddr == nil {
			continue
		}
		// 排除客户端自己
		if ct.ClientInfo.Callsign == transmitter.ClientInfo.Callsign {
			continue
		}
		// 排除没有标记为接受的客户端
		if !ct.ReceiveFlag {
			continue
		}
		candidates = append(candidates, broadcastCandidate{client: ct.ClientInfo.Client, addr: ct.ClientInfo.UDPAddr})
	}
	channel.ClientsMutex.RUnlock()

	defer func() {
		if controllersFromPool {
			controllers = controllers[:0]
			s.clientInterfaceSlicePool.Put(controllers)
		}
		if candidatesFromPool {
			candidates = candidates[:0]
			s.broadcastCandidateSlicePool.Put(candidates)
		}
	}()

	sender := transmitter.ClientInfo.Client
	seeingSender := s.clientInterfaceSlicePool.Get().([]fsd.ClientInterface)[:0]
	defer func() {
		seeingSender = seeingSender[:0]
		s.clientInterfaceSlicePool.Put(seeingSender)
	}()
	for _, ctrl := range controllers {
		if ctrl != nil && fsd.BroadcastToClientInRangeWithVoiceRange(ctrl, sender) {
			seeingSender = append(seeingSender, ctrl)
		}
	}
	addrMap := s.addrMapPool.Get().(map[string]*net.UDPAddr)
	utils.ClearMap(addrMap)
	defer func() {
		utils.ClearMap(addrMap)
		s.addrMapPool.Put(addrMap)
	}()
	for _, c := range candidates {
		inControllerRange := false
		for _, ctrl := range seeingSender {
			if fsd.BroadcastToClientInRangeWithVoiceRange(ctrl, c.client) {
				inControllerRange = true
				break
			}
		}
		if inControllerRange {
			addrMap[c.addr.String()] = c.addr
			continue
		}
		if fsd.BroadcastToClientInRangeWithVoiceRange(c.client, sender) {
			addrMap[c.addr.String()] = c.addr
		}
	}
	for _, addr := range addrMap {
		targets = append(targets, addr)
	}

	if len(targets) == 0 {
		return
	}

	s.broadcastToTargets(targets, packet.RawData, client)
}

func (s *VoiceServer) handleClientPacket(ctx context.Context, client *ClientInfo) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-client.Channel:
			if !ok {
				return
			}
			s.logger.DebugF("Received voice packet from %s: %+v", client.Callsign, packet)
			s.handleBroadcast(client, packet)
		}
	}
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
	data = append(data, '\n')
	_, err = conn.Write(data)
	if err != nil {
		s.logger.ErrorF("failed to write control message: %v", err)
	}
}

func (s *VoiceServer) cleanupClient(client *ClientInfo) {
	if client.Disconnected.Load() {
		return
	}

	close(client.Channel)

	for _, transmitter := range client.Transmitters {
		s.removeFromChannel(transmitter)
	}

	if client.Client.IsAtc() && !client.Client.IsAtis() {
		freq := ChannelFrequency(client.Client.Frequency() + 100000)
		s.channelsMutex.Lock()
		channel, exists := s.channels[freq]
		if exists && len(channel.Controllers) > 0 {
			channel.ClientsMutex.Lock()
			newControllers := channel.Controllers[:0]
			for _, ctrl := range channel.Controllers {
				if ctrl != nil && ctrl.Callsign() != client.Callsign {
					newControllers = append(newControllers, ctrl)
				}
			}
			channel.Controllers = newControllers
			channel.ClientsMutex.Unlock()
		}
		s.channelsMutex.Unlock()
	}

	s.clientsMutex.Lock()
	delete(s.clients, client.Cid)
	s.clientsMutex.Unlock()

	client.Client.SetAudioOnline(false)

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
		})
	}

	return client.Transmitters[transmitterID]
}

func (s *VoiceServer) addToChannel(transmitter *Transmitter) {
	channel := s.getOrCreateChannel(transmitter.Frequency)

	channel.ClientsMutex.Lock()
	channel.Clients[transmitter.ClientInfo.Callsign] = transmitter
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
			Clients:      make(map[string]*Transmitter),
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

	channel.ClientsMutex.Lock()
	delete(channel.Clients, transmitter.ClientInfo.Callsign)
	channel.ClientsMutex.Unlock()

	if len(channel.Clients) == 0 {
		delete(s.channels, channel.Frequency)
	}
}

const maxCallsignLen = 127

func (s *VoiceServer) buildAtisVoicePacket(cid int32, transmitter int8, frequency int32, callsign string, audio []byte) []byte {
	if len(callsign) > maxCallsignLen {
		callsign = callsign[:maxCallsignLen]
	}
	size := 4 + 1 + 4 + 1 + len(callsign) + len(audio)
	buf := make([]byte, 0, size)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(cid))
	buf = append(buf, byte(transmitter))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(frequency))
	buf = append(buf, byte(len(callsign)))
	buf = append(buf, callsign...)
	buf = append(buf, audio...)
	buf = append(buf, '\n')
	return buf
}

func (s *VoiceServer) broadcastATISVoicePacket(client *ATISClientInfo) (overflow bool) {
	client.VoiceFramesMutex.RLock()
	frame := client.VoiceFrames[client.VoiceFramesIndex.Load()]
	client.VoiceFramesMutex.RUnlock()
	client.VoiceFramesIndex.Add(1)
	if client.VoiceFramesIndex.Load() >= uint32(len(client.VoiceFrames)) {
		client.VoiceFramesIndex.Store(0)
		overflow = true
	}
	if frame == nil {
		client.ClientInfo.Logger.DebugF("Frame is nil")
		return
	}

	s.channelsMutex.RLock()
	channel, exists := s.channels[ChannelFrequency(client.Frequency)]
	s.channelsMutex.RUnlock()

	if !exists {
		client.ClientInfo.Logger.ErrorF("Channel %d not found from %s", client.Frequency, client.Callsign)
		return
	}

	targets := s.addressSlicePool.Get().([]*net.UDPAddr)[:0]
	defer s.addressSlicePool.Put(targets)

	channel.ClientsMutex.RLock()
	for _, transmitter := range channel.Clients {
		if transmitter.ClientInfo.UDPAddr == nil {
			continue
		}
		if transmitter.ClientInfo.Callsign == client.Callsign {
			continue
		}
		if !transmitter.ReceiveFlag {
			continue
		}
		if fsd.BroadcastToClientInRangeWithVoiceRange(client.Transmitter.ClientInfo.Client, transmitter.ClientInfo.Client) {
			targets = append(targets, transmitter.ClientInfo.UDPAddr)
		}
	}
	channel.ClientsMutex.RUnlock()

	s.broadcastToTargets(targets, frame, client.Transmitter.ClientInfo)
	return
}

func (s *VoiceServer) runAtisVoiceLoop(ctx context.Context, client *ATISClientInfo) {
	interval := time.Duration(s.config.OPUSFrameTime) * time.Millisecond
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if s.broadcastATISVoicePacket(client) {
				timer.Stop()
				time.AfterFunc(s.config.ATISPlayDuration, func() {
					timer.Reset(interval)
				})
			}
		}
	}
}

func (s *VoiceServer) startAtisVoice(client *ATISClientInfo) {
	ctx, cancel := context.WithCancel(s.ctx)
	client.CancelFunc = cancel
	go s.runAtisVoiceLoop(ctx, client)
	s.logger.InfoF("ATIS voice started for %s on frequency %d", client.Callsign, client.Frequency)
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
	c.ClientsMutex.Lock()
	defer c.ClientsMutex.Unlock()
	for _, ctrl := range c.Controllers {
		if ctrl != nil && ctrl.Callsign() == client.Callsign {
			return nil
		}
	}
	s.logger.InfoF("Adding channel %d controller %s(%04d)", freq, client.Callsign, client.Cid)
	c.Controllers = append(c.Controllers, client.Client)
	return nil
}

func (s *VoiceServer) recycleVoicePacket(packet *VoicePacket) {
	if cap(packet.RawData) == *global.VoicePoolSize {
		packet.RawData = packet.RawData[:*global.VoicePoolSize]
		s.voiceDataPool.Put(packet.RawData)
	} else if packet.RawData != nil {
		packet.RawData = nil
	}

	if cap(packet.Data) == *global.VoicePoolSize {
		packet.Data = packet.Data[:*global.VoicePoolSize]
		s.voiceDataPool.Put(packet.Data)
	} else if packet.Data != nil {
		packet.Data = nil
	}

	packet.Cid = 0
	packet.Transmitter = 0
	packet.Frequency = 0
	packet.Callsign = ""

	s.voicePacketPool.Put(packet)
}
