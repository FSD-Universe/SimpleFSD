package client

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type Client struct {
	socket                  SessionInterface
	logger                  log.LoggerInterface
	config                  *config.Config
	userOperation           operation.UserOperationInterface
	flightPlanOperation     operation.FlightPlanOperationInterface
	historyOperation        operation.HistoryOperationInterface
	capacities              map[string]bool
	isAtc                   bool
	isAtis                  bool
	logoffTime              string
	isBreak                 bool
	callsign                string
	rating                  Rating
	facility                Facility
	user                    *operation.User
	protocol                int
	realName                string
	position                [4]Position
	simType                 int
	transponder             string
	trueAltitude            int
	pressureAltitude        int
	groundSpeed             int
	frequency               int
	pbh                     uint32
	visualRange             float64
	flightPlan              *operation.FlightPlan
	atisInfo                []string
	paths                   []*PilotPath
	history                 *operation.History
	clientManager           ClientManagerInterface
	disconnect              atomic.Bool
	motdBytes               []byte
	reconnectTimer          *time.Timer
	lock                    sync.RWMutex
	deleteCallback          Callback
	disconnectCallback      Callback
	reconnectCallback       Callback
	messageReceivedCallback func([]byte)
	arrival                 bool
	arrivalAirportData      *config.AirportData
	arrivalAirportPosition  Position
}

func NewClient(
	applicationContent *interfaces.ApplicationContent,
	callsign string,
	rating Rating,
	protocol int,
	realName string,
	session SessionInterface,
	isAtc bool,
) ClientInterface {
	session.SetCallsign(callsign)
	var flightPlan *operation.FlightPlan = nil

	// 初始化操作和配置
	c := applicationContent.ConfigManager().Config()
	flightPlanOperation := applicationContent.Operations().FlightPlanOperation()
	userOperation := applicationContent.Operations().UserOperation()
	historyOperation := applicationContent.Operations().HistoryOperation()
	logger := applicationContent.Logger().FsdLogger()

	// 如果不是ATC且不是模拟器服务器，则尝试获取飞行计划
	if !isAtc && !c.Server.General.SimulatorServer {
		fp, err := flightPlanOperation.GetFlightPlanByCid(session.User().Cid)
		if errors.Is(err, operation.ErrFlightPlanNotFound) {
			logger.WarnF("No flight plan found for %s(%d)", callsign, session.User().Cid)
		} else if err != nil {
			logger.WarnF("Fail to get flight plan for %s(%d): %v", callsign, session.User().Cid, err)
		}
		flightPlan = fp
	}

	client := &Client{
		logger:              log.NewLoggerAdapter(logger, fmt.Sprintf("%s(%d)[%s]", callsign, session.User().Cid, session.ConnId())),
		config:              c,
		userOperation:       userOperation,
		flightPlanOperation: flightPlanOperation,
		historyOperation:    historyOperation,
		capacities:          make(map[string]bool),
		isAtc:               isAtc,
		isAtis:              strings.HasSuffix(callsign, "ATIS"),
		isBreak:             false,
		logoffTime:          "",
		callsign:            callsign,
		rating:              rating,
		facility:            0,
		user:                session.User(),
		protocol:            protocol,
		realName:            realName,
		socket:              session,
		position:            [4]Position{},
		simType:             0,
		transponder:         "2000",
		trueAltitude:        0,
		groundSpeed:         0,
		frequency:           99998,
		visualRange:         40,
		flightPlan:          flightPlan,
		atisInfo:            make([]string, 0, 4),
		paths:               make([]*PilotPath, 0),
		history:             historyOperation.NewHistory(session.User().Cid, callsign, isAtc),
		motdBytes:           nil,
		clientManager:       applicationContent.ClientManager(),
		disconnect:          atomic.Bool{},
		reconnectTimer:      nil,
		lock:                sync.RWMutex{},
		arrivalAirportData:  nil,
	}
	return client
}

func (client *Client) recordPathPoint() {
	if !client.position[0].PositionValid() {
		return
	}
	client.paths = append(client.paths, &PilotPath{
		Latitude:    client.position[0].Latitude,
		Longitude:   client.position[0].Longitude,
		Altitude:    client.trueAltitude,
		GroundSpeed: client.groundSpeed,
		Timestamp:   time.Now().Unix(),
	})
}

func (client *Client) Disconnected() bool {
	return client.disconnect.Load()
}

func (client *Client) Delete() {
	if !client.disconnect.Load() {
		return
	}

	client.lock.Lock()
	defer client.lock.Unlock()

	if client.reconnectTimer != nil {
		client.reconnectTimer.Stop()
		client.reconnectTimer = nil
	}

	defer func() {
		client.logger.Info("Client session deleted")
		if err := client.clientManager.DeleteClient(client.callsign); err != nil {
			client.logger.ErrorF("Failed to delete from client manager, %v", err)
		}
		if client.deleteCallback != nil {
			client.deleteCallback()
		}
	}()

	// 模拟机服务器不用执行后续操作
	if client.config.Server.General.SimulatorServer {
		return
	}

	// 断线后解锁飞行计划
	if !client.isAtc && client.flightPlan != nil {
		err := client.flightPlanOperation.UnlockFlightPlan(client.flightPlan)
		if err != nil {
			client.logger.Error("Failed to unlock flight plan")
		}

		// 如果判断飞机已在目的机场内，则删除计划
		if client.checkArrival() {
			err := client.flightPlanOperation.DeleteFlightPlan(client.flightPlan)
			if err != nil {
				client.logger.Error("Failed to delete flight plan")
			}
		}
	}

	// 不计入ATIS时长
	if client.isAtis {
		return
	}

	// 不计入OBS登录时长
	if client.facility == OBS {
		return
	}

	client.historyOperation.EndRecord(client.history)

	// 不计算小于指定秒数的记录
	if client.history.OnlineTime < *global.FsdRecordFilter {
		return
	}

	// 写入连线数据
	if err := client.historyOperation.SaveHistory(client.history); err != nil {
		client.logger.Error("Failed to end history: %v")
	}

	if client.isAtc {
		// 写入管制连线时长
		if err := client.userOperation.UpdateUserAtcTime(client.user, client.history.OnlineTime); err != nil {
			client.logger.Error("Failed to add ATC time: %v")
		}
	} else {
		// 写入机组连线时长
		if err := client.userOperation.UpdateUserPilotTime(client.user, client.history.OnlineTime); err != nil {
			client.logger.Error("Failed to add pilot time: %v")
		}
	}
}

func (client *Client) Reconnect(socket SessionInterface) bool {
	client.lock.Lock()
	defer client.lock.Unlock()

	if !client.disconnect.Load() {
		return false
	}

	client.logger.Info("Client reconnected")

	if client.reconnectTimer != nil {
		client.reconnectTimer.Stop()
		client.reconnectTimer = nil
	}

	client.ClearAtcAtisInfo()
	client.capacities = make(map[string]bool)
	client.disconnect.Store(false)
	client.socket = socket
	for i := 0; i < 4; i++ {
		client.position[i].ResetPosition()
	}
	socket.SetCallsign(client.callsign)
	if client.reconnectCallback != nil {
		client.reconnectCallback()
	}
	client.flightPlan = nil
	fp, err := client.flightPlanOperation.GetFlightPlanByCid(client.user.Cid)
	if err == nil {
		client.flightPlan = fp
	}
	return true
}

func (client *Client) MarkedDisconnect(immediate bool) {
	client.lock.Lock()
	defer func() {
		client.lock.Unlock()
		if immediate {
			client.Delete()
		}
	}()

	if !client.disconnect.CompareAndSwap(false, true) {
		return
	}

	// 关闭连接
	if client.socket.Conn() != nil {
		_ = client.socket.Conn().Close()
	}

	// 取消之前的定时器
	if client.reconnectTimer != nil {
		client.reconnectTimer.Stop()
	}

	if client.disconnectCallback != nil {
		client.disconnectCallback()
	}

	if immediate {
		return
	}

	client.motdBytes = client.motdBytes[:0]
	client.reconnectTimer = time.AfterFunc(client.config.Server.FSDServer.SessionCleanDuration, client.Delete)
	client.logger.InfoF("client disconnected, reconnect window: %v", client.config.Server.FSDServer.SessionCleanDuration)
}

func (client *Client) UpsertFlightPlan(flightPlanData []string) error {
	client.arrival = false
	client.arrivalAirportData = nil
	defer func() {
		if client.flightPlan == nil || client.config.IsSimulatorServer() {
			return
		}
		client.arrivalAirportData = client.config.GetAirportData(client.flightPlan.ArrivalAirport)
		client.arrivalAirportPosition = Position{Latitude: client.arrivalAirportData.Lat, Longitude: client.arrivalAirportData.Lon}
	}()
	if client.flightPlan == nil {
		flightPlan, err := client.flightPlanOperation.UpsertFlightPlan(client.user, client.callsign, flightPlanData)
		if err != nil {
			return err
		}
		client.flightPlan = flightPlan
		return nil
	}
	// 如果是模拟机服务器, 只创建就行
	if client.config.IsSimulatorServer() {
		return nil
	}
	if client.flightPlan.Locked {
		departureAirport := flightPlanData[5]
		arrivalAirport := flightPlanData[9]
		if client.flightPlan.DepartureAirport != departureAirport || client.flightPlan.ArrivalAirport != arrivalAirport {
			client.flightPlan.Locked = false
		}
	}
	client.flightPlan.Callsign = client.callsign
	err := client.flightPlanOperation.UpdateFlightPlan(client.flightPlan, flightPlanData, false)
	return err
}

func (client *Client) SetPosition(index int, lat float64, lon float64) error {
	if index >= 4 {
		return errors.New("position index out of range")
	}
	client.position[index].SetPosition(lat, lon)
	return nil
}

func (client *Client) checkArrival() bool {
	if client.arrivalAirportData != nil {
		return DistanceInNauticalMiles(client.position[0], client.arrivalAirportPosition) <= client.arrivalAirportData.AirportRange
	}
	return false
}

func (client *Client) UpdatePilotPos(transponder int, lat float64, lon float64, trueAlt int, pressAlt int, groundSpeed int, pbh uint32) {
	_ = client.SetPosition(0, lat, lon)
	client.transponder = fmt.Sprintf("%04d", transponder)
	client.trueAltitude = trueAlt
	client.pressureAltitude = pressAlt
	client.groundSpeed = groundSpeed
	client.pbh = pbh
	client.recordPathPoint()
}

func (client *Client) checkVisPoint() {
	for i := 1; i < 4; i++ {
		if !client.position[i].PositionValid() {
			continue
		}
		if client.position[i].LastUpdate.Before(time.Now().Add(-2 * time.Minute)) {
			client.logger.InfoF("expired position point %d", i)
			client.position[i].ResetPosition()
		}
	}
}

func (client *Client) UpdateAtcPos(frequency int, facility Facility, visualRange float64, lat float64, lon float64) {
	_ = client.SetPosition(0, lat, lon)
	client.frequency = frequency
	client.facility = facility
	client.visualRange = visualRange
	client.checkVisPoint()
}

func (client *Client) UpdateAtcVisPoint(visIndex int, lat float64, lon float64) error {
	if visIndex < 0 || visIndex > 2 {
		return errors.New("visIndex out of range [0,2]")
	}
	return client.SetPosition(visIndex+1, lat, lon)
}

func (client *Client) ClearAtcAtisInfo() {
	client.atisInfo = client.atisInfo[:0]
}

func (client *Client) AddAtcAtisInfo(atisInfo string) {
	client.atisInfo = append(client.atisInfo, atisInfo)
}

func (client *Client) SendError(result *Result) {
	if result.Success {
		return
	}

	var errString string
	if result.Errno == Custom {
		errString = result.Err.Error()
	} else {
		errString = result.Errno.String()
	}

	packet := MakePacket(Error, global.FSDServerName, client.callsign, fmt.Sprintf("%03d", result.Errno.Index()), result.Env, errString)
	client.SendLine(packet)

	if result.Fatal {
		client.socket.SetDisconnected(true)
		client.disconnect.Store(true)
		go client.Delete()
	}
}

func (client *Client) SendLineWithoutLog(line []byte) error {
	client.lock.RLock()
	defer client.lock.RUnlock()

	if client.disconnect.Load() {
		client.logger.Warn("Attempted send to disconnected client")
		return ErrClientDisconnected
	}

	if !bytes.HasSuffix(line, SplitSign) {
		line = append(line, SplitSign...)
	}

	if _, err := client.socket.Conn().Write(line); err != nil {
		client.logger.ErrorF("Failed to send data: %v", err)
		return ErrClientSocketWrite
	}

	if client.messageReceivedCallback != nil && bytes.HasPrefix(line, []byte(Message)) {
		_, result, _ := bytes.Cut(line, []byte(Message))
		go client.messageReceivedCallback(result)
	}
	return nil
}

func (client *Client) SendLine(line []byte) {
	if client.disconnect.Load() {
		client.logger.Debug("Attempted send to disconnected client")
		return
	}

	client.lock.RLock()
	defer client.lock.RUnlock()

	if !bytes.HasSuffix(line, SplitSign) {
		client.logger.DebugF("<- %s", line)
		line = append(line, SplitSign...)
	} else {
		client.logger.DebugF("<- %s", line[:len(line)-SplitSignLen])
	}

	if _, err := client.socket.Conn().Write(line); err != nil {
		client.logger.WarnF("Failed to send data: %v", client.callsign, err)
	}

	if client.messageReceivedCallback != nil && bytes.HasPrefix(line, []byte(Message)) {
		_, result, _ := bytes.Cut(line, []byte(Message))
		go client.messageReceivedCallback(result)
	}
}

func (client *Client) SendMotd() {
	if client.motdBytes != nil {
		client.SendLine(client.motdBytes)
		return
	}

	buffer := bytes.Buffer{}
	for _, message := range client.config.Server.FSDServer.CurrentMotd {
		buffer.Write(MakePacket(Message, global.FSDServerName, client.callsign, message))
	}

	client.motdBytes = buffer.Bytes()
	client.SendLine(client.motdBytes)
}

func (client *Client) UpdateCapacities(capacities []string) {
	for _, capacity := range capacities {
		caps := strings.Split(capacity, "=")
		if len(caps) != 2 {
			client.logger.WarnF("Invalid capacitiy: %s", capacity)
			continue
		}
		client.capacities[caps[0]] = utils.StrToInt(caps[1], 0) == 1
	}
}

func (client *Client) VoiceRange() float64 {
	if client.isAtc {
		return client.visualRange
	}
	distance := 1.23 * math.Sqrt(float64(client.trueAltitude))
	return math.Max(distance, client.config.Server.VoiceServer.MinimumPilotRange)
}

func (client *Client) CheckCapacity(capacity string) bool {
	return client.capacities[capacity]
}

func (client *Client) CheckFacility(facility Facility) bool {
	return facility.CheckFacility(client.facility)
}

func (client *Client) CheckRating(rating []Rating) bool {
	return slices.Contains(rating, client.rating)
}

func (client *Client) IsAtc() bool { return client.isAtc }

func (client *Client) IsAtis() bool { return client.isAtis }

func (client *Client) Callsign() string { return client.callsign }

func (client *Client) Rating() Rating { return client.rating }

func (client *Client) Facility() Facility { return client.facility }

func (client *Client) RealName() string { return client.realName }

func (client *Client) Position() [4]Position { return client.position }

func (client *Client) VisualRange() float64 { return client.visualRange }

func (client *Client) SetUser(user *operation.User) { client.user = user }

func (client *Client) SetSimType(simType int) { client.simType = simType }

func (client *Client) FlightPlan() *operation.FlightPlan { return client.flightPlan }

func (client *Client) User() *operation.User { return client.user }

func (client *Client) Frequency() int { return client.frequency }

func (client *Client) AtisInfo() []string { return client.atisInfo }

func (client *Client) History() *operation.History { return client.history }

func (client *Client) Transponder() string { return client.transponder }

func (client *Client) TrueAltitude() int { return client.trueAltitude }
func (client *Client) PressureAltitude() int {
	return client.pressureAltitude
}

func (client *Client) GroundSpeed() int { return client.groundSpeed }

func (client *Client) Posture() (float64, float64, float64, bool) {
	return utils.UnpackPBH(client.pbh)
}

func (client *Client) Paths() []*PilotPath {
	return client.paths
}

func (client *Client) LogoffTime() string {
	return client.logoffTime
}

func (client *Client) SetLogoffTime(time string) { client.logoffTime = time }

func (client *Client) IsBreak() bool { return client.isBreak }

func (client *Client) SetBreak(isBreak bool) { client.isBreak = isBreak }

func (client *Client) SetRating(rating Rating) { client.rating = rating }

func (client *Client) SetRealName(realName string) { client.realName = realName }

func (client *Client) ClearFlightPlan() {
	client.flightPlan = nil
}

func (client *Client) SetFlightPlan(flightPlan *operation.FlightPlan) {
	client.flightPlan = flightPlan
	go client.clientManager.BroadcastMessage([]byte(client.flightPlanOperation.ToString(flightPlan)), client, BroadcastToAtc)
}

func (client *Client) SetDeleteCallback(deleteCallback Callback) {
	client.deleteCallback = deleteCallback
}

func (client *Client) SetDisconnectCallback(disconnectCallback Callback) {
	client.disconnectCallback = disconnectCallback
}

func (client *Client) SetReconnectCallback(reconnectCallback Callback) {
	client.reconnectCallback = reconnectCallback
}

func (client *Client) SetMessageReceivedCallback(messageReceivedCallback func([]byte)) {
	client.messageReceivedCallback = messageReceivedCallback
}
