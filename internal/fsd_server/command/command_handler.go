// Package command
package command

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	c "github.com/half-nothing/simple-fsd/internal/fsd_server/client"
	"github.com/half-nothing/simple-fsd/internal/interfaces"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

func (content *CommandContent) verifyFsdUserInfo(session SessionInterface, callsign string, protocol int, cid operation.UserId, password string) *Result {
	if !callsignValid(callsign) {
		return ResultError(CallsignInvalid, true, callsign, nil)
	}

	if protocol != 9 && protocol != 101 {
		return ResultError(InvalidProtocolVision, true, callsign, nil)
	}

	user, err := cid.GetUser(content.userOperation)
	if err != nil {
		return ResultError(InvalidCidPassword, true, callsign, err)
	}
	if user.Rating <= Ban.Index() {
		return ResultError(CidSuspended, true, callsign, nil)
	}
	if !content.userOperation.VerifyUserPassword(user, password) {
		return ResultError(InvalidCidPassword, true, callsign, nil)
	}

	client, ok := content.clientManager.GetClient(callsign)

	// 客户端存在
	if ok {
		if client.User().Cid != user.Cid {
			// 呼号一致但是cid不同，不属于重连
		} else if client.Reconnect(session) {
			// 重设重连客户端的User
			client.SetUser(user)
			// 客户端重连
			session.SetClient(client)
		} else {
			// 呼号已被使用
			return ResultError(CallsignInUse, true, callsign, nil)
		}
	}

	session.SetUser(user)

	return nil
}

func (content *CommandContent) verifyVatsimUserInfo(session SessionInterface, callsign string, cid operation.UserId, token string) *Result {
	if !callsignValid(callsign) {
		return ResultError(CallsignInvalid, true, callsign, nil)
	}

	user, err := cid.GetUser(content.userOperation)
	if err != nil {
		return ResultError(InvalidCidPassword, true, callsign, err)
	}
	if user.Rating <= Ban.Index() {
		return ResultError(CidSuspended, true, callsign, nil)
	}

	claims, err := jwt.ParseWithClaims(token, &service.FsdClaims{}, content.defaultKeyFunc)
	if err != nil {
		return ResultError(InvalidCidPassword, true, callsign, err)
	}

	if _, ok := claims.Claims.(*service.FsdClaims); !ok {
		return ResultError(InvalidCidPassword, true, callsign, errors.New("invalid claims type"))
	}

	client, ok := content.clientManager.GetClient(callsign)

	// 客户端存在
	if ok {
		if client.User().Cid != user.Cid {
			// 呼号一致但是cid不同，不属于重连
		} else if client.Reconnect(session) {
			// 客户端重连
			client.SetUser(user)
			session.SetClient(client)
		} else {
			// 呼号已被使用
			return ResultError(CallsignInUse, true, callsign, nil)
		}
	}

	session.SetUser(user)

	return nil
}

func (content *CommandContent) checkRangeLimit(_ SessionInterface, realFacility Facility, realRange int) *Result {
	rangeLimit := realFacility.GetRangeLimit()
	if rangeLimit > -1 && realRange > rangeLimit {
		return ResultError(Custom, content.refuseOutRange, strconv.Itoa(realRange), fmt.Errorf("visual range out of limit, your visual range is %d but limit is %d", realRange, rangeLimit))
	}
	return nil
}

func (content *CommandContent) defaultKeyFunc(token *jwt.Token) (interface{}, error) {
	if token.Method.Alg() != global.SigningMethod {
		return nil, errors.New("illegal signature methods")
	}
	return []byte(content.jwtToken), nil
}

func (content *CommandContent) checkRatingAndFacility(session SessionInterface, reqRating int, callsign string) *Result {
	if reqRating > session.User().Rating {
		return ResultError(RequestLevelTooHigh, true, callsign, nil)
	}
	facilityIdent := strings.Split(callsign, "_")
	if len(facilityIdent) < 2 {
		return ResultError(Custom, true, callsign, fmt.Errorf("invalid callsign %s", callsign))
	}
	ident := facilityIdent[len(facilityIdent)-1]
	if facility, exist := FacilityMap[ident]; !exist {
		return ResultError(Custom, true, callsign, fmt.Errorf("invalid callsign %s", callsign))
	} else {
		session.SetFacilityIdent(facility)
	}
	return nil
}

func (content *CommandContent) HandleVatsimAddAtc(session SessionInterface, data []string, _ []byte) *Result {
	callsign := data[0]
	cid := operation.GetUserId(data[3])
	if result := content.verifyVatsimUserInfo(session, callsign, cid, data[4]); result != nil {
		return result
	}
	reqRating := utils.StrToInt(data[5], 0)
	if result := content.checkRatingAndFacility(session, reqRating, callsign); result != nil {
		return result
	}
	realName := data[2]
	if session.Client() == nil {
		client := c.NewClient(content.application, callsign, Rating(reqRating), 0, realName, session, true)
		_ = content.clientManager.AddClient(client)
		session.SetClient(client)
	} else {
		session.Client().SetRating(Rating(reqRating))
		session.Client().SetRealName(realName)
	}
	content.logger.InfoF("[%s] ATC login successfully", callsign)
	broadcastData := data[:6]
	broadcastData[4] = ""
	go content.clientManager.BroadcastMessage(MakePacket(AddAtc, broadcastData...), session.Client(), BroadcastToClientInRange)
	session.Client().SendMotd()
	session.Client().SendLine(MakePacket(ClientQuery, global.ATISManagerName, callsign, "ATIS"))
	return ResultSuccess()
}

func (content *CommandContent) HandleFsdAddAtc(session SessionInterface, data []string, _ []byte) *Result {
	callsign := data[0]
	cid := operation.GetUserId(data[3])
	password := data[4]
	protocol := utils.StrToInt(data[6], 0)
	if result := content.verifyFsdUserInfo(session, callsign, protocol, cid, password); result != nil {
		return result
	}
	reqRating := utils.StrToInt(data[5], 0)
	if result := content.checkRatingAndFacility(session, reqRating, callsign); result != nil {
		return result
	}
	realName := data[2]
	latitude := utils.StrToFloat(data[9], 0)
	longitude := utils.StrToFloat(data[10], 0)
	if session.Client() == nil {
		client := c.NewClient(content.application, callsign, Rating(reqRating), protocol, realName, session, true)
		_ = client.SetPosition(0, latitude, longitude)
		_ = content.clientManager.AddClient(client)
		session.SetClient(client)
	} else {
		session.Client().SetRating(Rating(reqRating))
		session.Client().SetRealName(realName)
	}
	content.logger.InfoF("[%s] ATC login successfully", callsign)
	broadcastData := data[:6]
	broadcastData[4] = ""
	go content.clientManager.BroadcastMessage(MakePacket(AddAtc, broadcastData...), session.Client(), BroadcastToClientInRange)
	session.Client().SendMotd()
	session.Client().SendLine(MakePacket(ClientQuery, global.ATISManagerName, callsign, AtcAtis))
	return ResultSuccess()
}

func (content *CommandContent) HandleVatsimAddPilot(session SessionInterface, data []string, rawLine []byte) *Result {
	callsign := data[0]
	cid := operation.GetUserId(data[2])
	if result := content.verifyVatsimUserInfo(session, callsign, cid, data[3]); result != nil {
		return result
	}
	return content.handleClientLogin(session, data, rawLine, callsign, utils.StrToInt(data[5], 0))
}

func (content *CommandContent) HandleFsdAddPilot(session SessionInterface, data []string, rawLine []byte) *Result {
	callsign := data[0]
	cid := operation.GetUserId(data[2])
	password := data[3]
	protocol := utils.StrToInt(data[5], 0)
	result := content.verifyFsdUserInfo(session, callsign, protocol, cid, password)
	if result != nil {
		return result
	}
	return content.handleClientLogin(session, data, rawLine, callsign, protocol)
}

func (content *CommandContent) handleClientLogin(session SessionInterface, data []string, _ []byte, callsign string, protocol int) *Result {
	simType := utils.StrToInt(data[6], 0)
	realName := data[7]
	reqRating := Rating(utils.StrToInt(data[4], 0) - 1)
	if reqRating != Normal || !RatingFacilityMap[reqRating].CheckFacility(Pilot) {
		return ResultError(RequestLevelTooHigh, true, callsign, nil)
	}
	if session.Client() == nil {
		client := c.NewClient(content.application, callsign, reqRating, protocol, realName, session, false)
		client.SetSimType(simType)
		session.SetClient(client)
		_ = content.clientManager.AddClient(client)
	} else {
		session.Client().SetRating(reqRating)
		session.Client().SetRealName(realName)
	}
	content.logger.InfoF("[%s] Client login successfully", callsign)
	broadcastData := data[:6]
	broadcastData[4] = ""
	go content.clientManager.BroadcastMessage(MakePacket(AddPilot, broadcastData...), session.Client(), BroadcastToClientInRange)
	session.Client().SendMotd()
	session.Client().SendLine(MakePacket(ClientQuery, global.ATISManagerName, callsign, ClientCapacity))
	if !content.isSimulatorServer {
		flightPlan := session.Client().FlightPlan()
		if flightPlan != nil && flightPlan.FromWeb && callsign != flightPlan.Callsign &&
			flightPlan.UpdatedAt.Add(time.Hour).After(time.Now()) {
			session.Client().SendLine(MakePacket(Message, "FPlanManager", callsign,
				fmt.Sprintf("Seems you are connect with callsign(%s), "+
					"but we found a flightplan submit by web at %s which has callsign(%s), "+
					"please check it.", callsign, flightPlan.UpdatedAt.Format(time.DateTime), flightPlan.Callsign)))
		}
	}
	return ResultSuccess()
}

func (content *CommandContent) HandleAtcPosUpdate(session SessionInterface, data []string, rawLine []byte) *Result {
	callsign := data[0]
	rating := Rating(utils.StrToInt(data[4], 0))
	facility := Facility(1 << utils.StrToInt(data[2], 0))
	// 检查权限能否匹配席位
	// 比如用OBS权限上FSS席位
	// 这里的席位指的是es上设置的席位
	if !rating.CheckRatingFacility(facility) {
		return ResultError(RequestLevelTooHigh, true, callsign, nil)
	}
	// 这里也是检查权限能否匹配席位
	// 比如用SUP权限上ADM席位
	// 这里的席位指的是通过呼号判断的席位
	if !rating.CheckRatingFacility(session.FacilityIdent()) {
		return ResultError(CallsignInvalid, true, callsign, errors.New("callsign and faility mismatch"))
	}
	if res := content.checkRangeLimit(session, facility, utils.StrToInt(data[3], 0)); res != nil {
		return res
	}
	frequency := utils.StrToInt(data[1], 0)
	visualRange := utils.StrToFloat(data[3], 0)
	latitude := utils.StrToFloat(data[5], 0)
	longitude := utils.StrToFloat(data[6], 0)
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	go content.clientManager.BroadcastMessage(rawLine, session.Client(), BroadcastToClientInRange)
	session.Client().UpdateAtcPos(frequency, facility, visualRange, latitude, longitude)
	return ResultSuccess()
}

func (content *CommandContent) HandlePilotPosUpdate(session SessionInterface, data []string, rawLine []byte) *Result {
	transponder := utils.StrToInt(data[2], 0)
	latitude := utils.StrToFloat(data[4], 0)
	longitude := utils.StrToFloat(data[5], 0)
	altitude := utils.StrToInt(data[6], 0)
	groundSpeed := utils.StrToInt(data[7], 0)
	pbh := uint32(utils.StrToInt(data[8], 0))
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	go content.clientManager.BroadcastMessage(rawLine, session.Client(), BroadcastToClientInRange)
	session.Client().UpdatePilotPos(transponder, latitude, longitude, altitude, groundSpeed, pbh)
	return ResultSuccess()
}

func (content *CommandContent) HandleAtcVisPointUpdate(session SessionInterface, data []string, _ []byte) *Result {
	visPos := utils.StrToInt(data[1], 0)
	latitude := utils.StrToFloat(data[2], 0)
	longitude := utils.StrToFloat(data[3], 0)
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	_ = session.Client().UpdateAtcVisPoint(visPos, latitude, longitude)
	return ResultSuccess()
}

// sendFrequencyMessage 发送频率消息
func (content *CommandContent) sendFrequencyMessage(session SessionInterface, targetStation string, rawLine []byte) *Result {
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	// 如果目标频率是@94836
	// 说明是客户端广播，转发给所有客户端
	if targetStation == ClientQueryBroadcastFrequencyClient {
		go content.clientManager.BroadcastMessage(rawLine, session.Client(), BroadcastToClientInRange)
		return ResultSuccess()
	}
	// 如果目标频率是94835
	// 说明是管制员广播，转发给所有管制员
	if targetStation == ClientQueryBroadcastFrequency {
		go content.clientManager.BroadcastMessage(rawLine, session.Client(), CombineBroadcastFilter(BroadcastToAtc, BroadcastToClientInRange))
		return ResultSuccess()
	}
	frequency := utils.StrToInt(fmt.Sprintf("%d%s", 1, targetStation[1:]), -1)
	if frequency == -1 {
		return ResultError(Syntax, true, targetStation, fmt.Errorf("illegal frequency %s", targetStation))
	}
	if FrequencyValid(frequency) {
		// 合法频率, 发给所有客户端
		go content.clientManager.BroadcastMessage(rawLine, session.Client(), BroadcastToClientInRange)
	} else {
		// 非法频率, 这里应该不予转发
		// 但考虑到可能有插件自定义频率，故转发给管制员
		go content.clientManager.BroadcastMessage(rawLine, session.Client(), CombineBroadcastFilter(BroadcastToAtc, BroadcastToClientInRange))
	}
	return ResultSuccess()
}

func (content *CommandContent) HandleClientQuery(session SessionInterface, data []string, rawLine []byte) *Result {
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	commandLength := len(data)
	if commandLength < 3 {
		return ResultError(Syntax, false, "", fmt.Errorf("illegal command length %d", commandLength))
	}
	targetStation := data[1]
	// 发给服务器的查询，处理后不转发
	if targetStation == global.FSDServerName {
		subQuery := data[2]
		// 查询指定机组的飞行计划
		switch subQuery {
		case ClientFlightPlan:
			if commandLength < 4 {
				return ResultError(Syntax, false, "", fmt.Errorf("illegal command length %d", commandLength))
			}
			targetCallsign := data[3]
			client, ok := content.clientManager.GetClient(targetCallsign)
			if !ok || client.FlightPlan() == nil {
				return ResultError(NoFlightPlan, false, session.Client().Callsign(), nil)
			}
			session.Client().SendLine([]byte(content.flightPlanOperation.ToString(client.FlightPlan())))
		case AvailableAtc:
			if isValidAtc(data[3]) {
				session.Client().SendLine(MakePacket(ClientResponse, global.FSDServerName, data[0], "ATC:Y", data[3]))
			} else {
				session.Client().SendLine(MakePacket(ClientResponse, global.FSDServerName, data[0], "ATC:N", data[3]))
			}
		case ClientCapacity:
			if session.Client().IsAtc() {
				session.Client().SendLine(MakePacket(ClientResponse, global.FSDServerName, data[0], "CAPS:ATCINFO=1:SECPOS=1:FASTPOS=1:OBSPILOT=1"))
			} else {
				session.Client().SendLine(MakePacket(ClientResponse, global.FSDServerName, data[0], "CAPS:VERSION=1:ATCINFO=1:MODELDESC=1:ACCONFIG=1:VISUPDATE=1"))
			}
		case IpAddress:
			session.Client().SendLine(MakePacket(ClientResponse, global.FSDServerName, data[0], "IP", session.Conn().RemoteAddr().String()[0:strings.LastIndex(session.Conn().RemoteAddr().String(), ":")]))
		}
		return ResultSuccess()
	}
	// 如果发送目标是一个频率
	if strings.HasPrefix(targetStation, "@") {
		// 如果目标频率是94835
		// 说明是管制员广播，更新存储的信息
		if targetStation == ClientQueryBroadcastFrequency {
			subQuery := data[2]
			// OBS接牌子直接踢下线
			if subQuery == ITakeTag && (session.Client().Rating() <= Observer || session.Client().Facility() <= OBS) {
				return ResultError(InvalidCtrl, true, session.Client().Callsign(), nil)
			}
			if !content.isSimulatorServer {
				// 如果是编辑飞行计划
				if subQuery == EditFlightPlan && commandLength >= 5 {
					content.handleFlightPlanEdit(data, rawLine)
				}
			}
			// ATIS信息更新, 需要更新服务器存储的ATIS信息
			if subQuery == InfoUpdate {
				session.Client().ClearAtcAtisInfo()
				session.Client().SendLine(MakePacket(ClientQuery, global.ATISManagerName, session.Callsign(), AtcAtis))
			}
			if subQuery == Break {
				session.Client().SetBreak(true)
			}
			if subQuery == NoBreak {
				session.Client().SetBreak(false)
			}
		}
		return content.sendFrequencyMessage(session, targetStation, rawLine)
	} else {
		_ = content.clientManager.SendMessageTo(targetStation, rawLine)
	}
	return ResultSuccess()
}

func (content *CommandContent) handleFlightPlanEdit(data []string, rawLine []byte) {
	targetCallsign := data[3]
	client, ok := content.clientManager.GetClient(targetCallsign)
	if !ok {
		// 这里并不是发给服务器的, 所以如果找不到指定客户端, 直接返回就行
		return
	}
	if client.FlightPlan() == nil {
		// 这里并不是发给服务器的, 所以如果出错, 什么都不用做
		return
	}
	cruiseAltitude := utils.StrToInt(data[4], -1)
	if cruiseAltitude == -1 || cruiseAltitude == 0 {
		// 这里并不是发给服务器的, 所以如果出错, 什么都不用做
		content.logger.ErrorF("UpdateCruiseAltitude error: illegal cruise altitude %s, %s", data[4], rawLine)
		return
	}
	_ = content.flightPlanOperation.UpdateCruiseAltitude(client.FlightPlan(), fmt.Sprintf("FL%03d", cruiseAltitude/100))
	return
}

func (content *CommandContent) HandleClientResponse(session SessionInterface, data []string, rawLine []byte) *Result {
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	commandLength := len(data)
	targetStation := data[1]
	// 对服务器查询的回复，处理后不转发
	if targetStation == global.FSDServerName {
		subQuery := data[2]
		if subQuery == ClientCapacity && commandLength >= 4 {
			session.Client().UpdateCapacities(data[3:])
			if *global.VisualPilot && session.Client().CheckCapacity(VisualPilot) {
				session.Client().SendLine(MakePacket(SwitchVisualPilot, global.FSDServerName, session.Callsign(), "1"))
			}
			return ResultSuccess()
		}
		return ResultSuccess()
	}
	// 对ATISManager的ATIS信息回复，处理后不转发
	if targetStation == global.ATISManagerName {
		subQuery := data[2]
		if subQuery == AtcAtis && commandLength >= 5 {
			if data[3] == "T" {
				session.Client().AddAtcAtisInfo(data[4])
			}
			if data[3] == "Z" {
				session.Client().SetLogoffTime(data[4])
			}
			return ResultSuccess()
		}
		return ResultSuccess()
	}
	if strings.HasPrefix(targetStation, "@") {
		return content.sendFrequencyMessage(session, targetStation, rawLine)
	} else {
		_ = content.clientManager.SendMessageTo(targetStation, rawLine)
		return ResultSuccess()
	}
}

func (content *CommandContent) HandleMessage(session SessionInterface, data []string, rawLine []byte) *Result {
	targetStation := data[1]
	if targetStation == global.ATISManagerName {
		if strings.HasSuffix(data[2], "z") {
			session.Client().SetLogoffTime(strings.TrimRight(data[2], "z"))
			return ResultSuccess()
		}
		session.Client().AddAtcAtisInfo(data[2])
		return ResultSuccess()
	}
	if strings.HasPrefix(targetStation, "@") {
		result := content.sendFrequencyMessage(session, targetStation, rawLine)
		if result != nil {
			return result
		}
		return ResultSuccess()
	}
	if strings.HasPrefix(targetStation, "*") {
		// 广播消息
		if targetStation == string(AllSup) {
			go content.clientManager.BroadcastMessage(rawLine, session.Client(), BroadcastToSup)
			return ResultSuccess()
		}
		if targetStation == "*" && session.Client().IsAtc() && session.Client().CheckRating(AllowKillRating) {
			go content.clientManager.BroadcastMessage(rawLine, session.Client(), BroadcastToAll)
		}
		return ResultSuccess()
	}
	_ = content.clientManager.SendMessageTo(targetStation, rawLine)
	return ResultSuccess()
}

func (content *CommandContent) HandlePlan(session SessionInterface, data []string, rawLine []byte) *Result {
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	if session.Client().IsAtc() {
		return ResultError(Syntax, false, "FLIGHT_PLAN", fmt.Errorf("atc can not submit fligth plan"))
	}
	if err := session.Client().UpsertFlightPlan(data); err != nil {
		return ResultError(Custom, false, "FLIGHT_PLAN", err)
	}
	if !session.Client().FlightPlan().Locked {
		go content.clientManager.BroadcastMessage(rawLine, session.Client(), CombineBroadcastFilter(BroadcastToAtc, BroadcastToClientInRange))
	} else {
		go content.clientManager.BroadcastMessage(
			[]byte(content.flightPlanOperation.ToString(session.Client().FlightPlan())),
			session.Client(),
			CombineBroadcastFilter(BroadcastToAtc, BroadcastToClientInRange),
		)
	}
	return ResultSuccess()
}

func (content *CommandContent) HandleAtcEditPlan(session SessionInterface, data []string, _ []byte) *Result {
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	if !session.Client().IsAtc() {
		return ResultError(Syntax, false, session.Client().Callsign(), fmt.Errorf("only atc can edit flight plan"))
	}
	if !session.Client().CheckFacility(AllowAtcFacility) {
		return ResultError(Syntax, false, session.Client().Callsign(), fmt.Errorf("%s facility not allowed to edit plan", session.Client().Facility().String()))
	}
	targetCallsign := data[2]
	client, ok := content.clientManager.GetClient(targetCallsign)
	if !ok {
		return ResultError(NoCallsignFound, false, session.Client().Callsign(), fmt.Errorf("%s not exists", targetCallsign))
	}
	if client.FlightPlan() == nil {
		return ResultError(NoFlightPlan, false, session.Client().Callsign(), fmt.Errorf("%s do not have filght plan", session.Client().Callsign()))
	}
	client.FlightPlan().Locked = !content.isSimulatorServer
	if err := content.flightPlanOperation.UpdateFlightPlan(client.FlightPlan(), data[1:], true); err != nil {
		return ResultError(Syntax, false, session.Client().Callsign(), err)
	}
	go content.clientManager.BroadcastMessage([]byte(content.flightPlanOperation.ToString(client.FlightPlan())),
		session.Client(), CombineBroadcastFilter(BroadcastToAtc, BroadcastToClientInRange))
	return ResultSuccess()
}

func (content *CommandContent) HandleKillClient(session SessionInterface, data []string, _ []byte) *Result {
	if session.Client() == nil {
		return ResultError(Custom, false, "", fmt.Errorf("client not register"))
	}
	if !(session.Client().IsAtc() && session.Client().CheckRating(AllowKillRating)) {
		return ResultError(Custom, false, session.Client().Callsign(), fmt.Errorf("%s rating not allowed to kill client", session.Client().Rating().String()))
	}
	targetStation := data[1]
	client, err := content.clientManager.KickClientFromServer(targetStation, data[2])
	if err != nil {
		return ResultError(NoCallsignFound, false, session.Client().Callsign(), fmt.Errorf("%s not exists", targetStation))
	}
	content.messageQueue.Publish(&queue.Message{
		Type: queue.SendKickedFromServerEmail,
		Data: &interfaces.KickedFromServerEmailData{
			User:     client.User(),
			Operator: session.User(),
			Reason:   data[2],
		},
	})
	content.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: content.auditLogOperation.NewAuditLog(
			operation.ClientKickedFsd,
			session.User().Cid,
			fmt.Sprintf("%s(%04d)", client.Callsign(), client.User().Cid),
			session.ConnId(),
			"NOT AVAILABLE",
			nil,
		),
	})
	return ResultSuccess()
}

func (content *CommandContent) HandleRequest(_ SessionInterface, data []string, rawLine []byte) *Result {
	targetStation := data[1]
	_ = content.clientManager.SendMessageTo(targetStation, rawLine)
	return ResultSuccess()
}

func (content *CommandContent) RemoveClient(session SessionInterface, _ []string, _ []byte) *Result {
	if session.Client() == nil {
		return ResultError(Custom, false, "", fmt.Errorf("client not register"))
	}
	content.logger.InfoF("[%s] Offline", session.Client().Callsign())
	return ResultSuccess()
}

func (content *CommandContent) HandleSquawkBox(session SessionInterface, data []string, rawLine []byte) *Result {
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	targetStation := data[1]
	client, ok := content.clientManager.GetClient(targetStation)
	if !ok {
		return ResultError(NoCallsignFound, false, session.Client().Callsign(), fmt.Errorf("%s not exists", targetStation))
	}
	client.SendLine(rawLine)
	return ResultSuccess()
}

func (content *CommandContent) HandleWeatherQuery(session SessionInterface, data []string, _ []byte) *Result {
	if session.Client() == nil {
		return ResultError(Syntax, false, "", fmt.Errorf("client not register"))
	}
	targetStation := data[3]
	if len(targetStation) != 4 {
		return ResultError(Syntax, false, targetStation, fmt.Errorf("invalid target station"))
	}
	result, err := content.metarManager.QueryMetar(targetStation)
	if err != nil {
		return ResultError(NoWeatherProfile, false, targetStation, fmt.Errorf("cant fetch metar for %s", targetStation))
	} else {
		session.Client().SendLine(MakePacket(WeatherResponse, global.FSDServerName, session.Callsign(), "METAR", result[6:]))
	}
	return ResultSuccess()
}

func (content *CommandContent) HandleClientIdent(session SessionInterface, data []string, _ []byte) *Result {
	session.SetCallsign(data[0])
	return ResultSuccess()
}

func (content *CommandContent) HandleBroadcastToClient(session SessionInterface, _ []string, rawLine []byte) *Result {
	go content.clientManager.BroadcastMessage(rawLine, session.Client(), CombineBroadcastFilter(BroadcastToPilot, BroadcastToClientInRange))
	return ResultSuccess()
}
