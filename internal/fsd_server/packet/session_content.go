// Package packet
package packet

import (
	"bufio"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	. "github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
)

type SessionContent struct {
	logger           log.LoggerInterface
	commandHandler   CommandHandlerInterface
	clientManager    ClientManagerInterface
	heartbeatTimeout time.Duration
	simulatorServer  bool
	possibleCommands [][]byte
	pool             *sync.Pool
}

func NewSessionContent(
	logger log.LoggerInterface,
	commandHandler CommandHandlerInterface,
	clientManager ClientManagerInterface,
	heartbeatTimeout time.Duration,
	simulatorServer bool,
) *SessionContent {
	content := &SessionContent{
		logger:           log.NewLoggerAdapter(logger, "SessionManager"),
		commandHandler:   commandHandler,
		clientManager:    clientManager,
		heartbeatTimeout: heartbeatTimeout,
		pool: &sync.Pool{New: func() interface{} {
			return make([]byte, 1<<12) // 4KB
		}},
		simulatorServer: simulatorServer,
	}
	content.possibleCommands = commandHandler.GetPossibleCommands()
	return content
}

func (content *SessionContent) SendError(session *Session, result *Result) {
	if result.Success {
		return
	}
	if session.client != nil {
		session.client.SendError(result)
		return
	}

	var errString string
	if result.Errno == Custom {
		errString = result.Err.Error()
	} else {
		errString = result.Errno.String()
	}

	packet := MakePacket(Error, global.FSDServerName, session.callsign, fmt.Sprintf("%03d", result.Errno.Index()), result.Env, errString)
	content.logger.DebugF("[%s](%s) <- %s", session.connId, session.callsign, packet[:len(packet)-SplitSignLen])
	if session.conn != nil {
		_, _ = session.conn.Write(packet)
	}
	if result.Fatal {
		session.close.Store(true)
	}
}

func (content *SessionContent) handleCommand(session *Session, commandType ClientCommand, data []string, rawLine []byte) *Result {
	if rawLine == nil {
		return ResultError(Syntax, false, string(commandType), errors.New("parse command failed"))
	}
	res := content.commandHandler.Call(commandType, session, data, rawLine)
	if res == nil {
		return ResultError(Syntax, false, string(commandType), errors.New("handle command failed"))
	}
	return res
}

func (content *SessionContent) handleLine(session *Session, line []byte) {
	if session.close.Load() {
		return
	}
	command, data := parserCommandLine(line, content.possibleCommands)
	if command == Unknown {
		content.logger.WarnF("[%s](%s) unknown command line %s", session.connId, session.callsign, line)
		return
	}
	result := content.handleCommand(session, command, data, line)
	if result == nil {
		content.logger.WarnF("[%s](%s) command handler return a nil result, %s", session.connId, session.callsign, line)
		return
	}
	if !result.Success {
		content.logger.ErrorF("[%s](%s) command handle fail, %s, %s, %s", session.connId, session.callsign, result.Errno.String(), result.Err.Error(), line)
		content.SendError(session, result)
	}
}

func (content *SessionContent) HandleConnection(session *Session) {
	if !*global.DebugMode {
		defer func() {
			if r := recover(); r != nil {
				buf := content.pool.Get().([]byte)
				stackSize := runtime.Stack(buf, false)
				content.logger.ErrorF("Recovered from panic: %v", r)
				content.logger.ErrorF("Stack trace: %s", buf[:stackSize])
				content.pool.Put(buf)
			}
		}()
	}
	defer func() {
		time.AfterFunc(global.FSDDisconnectDelay, func() {
			content.logger.DebugF("[%s](%s) x Connection closed", session.connId, session.callsign)
			if err := session.conn.Close(); err != nil && !isNetClosedError(err) {
				content.logger.WarnF("[%s](%s) Error occurred while closing connection, details: %v", session.connId, session.callsign, err)
			}
		})
	}()

	if *global.Vatsim {
		if content.simulatorServer && *global.VatsimFull {
			_, _ = session.conn.Write([]byte("$DISERVER:CLIENT:VATSIM FSD Sweatbox V3.42f:c8c46fcb3f1ac7334769fa\r\n"))
		} else {
			_, _ = session.conn.Write([]byte("$DISERVER:CLIENT:VATSIM FSD V3.53a:14d0434b96\r\n"))
		}
	}
	scanner := bufio.NewScanner(session.conn)
	scanner.Split(createSplitFunc(SplitSign))
	_ = session.conn.SetDeadline(time.Now().Add(content.heartbeatTimeout))
	for scanner.Scan() {
		_ = session.conn.SetDeadline(time.Now().Add(content.heartbeatTimeout))
		if scanner.Err() != nil {
			content.logger.ErrorF("[%s](%s) Error while scanning, %v", session.connId, session.callsign, scanner.Err())
			break
		}
		line := scanner.Bytes()
		content.logger.DebugF("[%s](%s) -> %s", session.connId, session.callsign, line)
		if session.client == nil || !*global.MutilThread {
			content.handleLine(session, line)
		} else {
			go content.handleLine(session, line)
		}
		if session.close.Load() {
			break
		}
	}

	if session.client != nil {
		if session.client.IsAtc() {
			go content.clientManager.BroadcastMessage(MakePacketWithoutSign(RemoveAtc, session.client.Callsign(), fmt.Sprintf("%04d", session.user.Cid)), session.client, BroadcastToClientInRange)
		} else {
			go content.clientManager.BroadcastMessage(MakePacketWithoutSign(RemovePilot, session.client.Callsign(), fmt.Sprintf("%04d", session.user.Cid)), session.client, BroadcastToClientInRange)
		}
		session.client.MarkedDisconnect(false)
	}
}
