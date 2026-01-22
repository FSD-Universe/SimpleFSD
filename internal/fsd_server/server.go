package fsd_server

import (
	"context"
	"net"
	"time"

	"github.com/half-nothing/simple-fsd/internal/fsd_server/command"
	"github.com/half-nothing/simple-fsd/internal/fsd_server/packet"
	. "github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
)

type ShutdownCallback struct {
	clientManager fsd.ClientManagerInterface
}

func NewShutdownCallback(clientManager fsd.ClientManagerInterface) *ShutdownCallback {
	return &ShutdownCallback{clientManager: clientManager}
}

func (dc *ShutdownCallback) Invoke(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		if err := dc.clientManager.Shutdown(timeoutCtx); err != nil {
			return
		}
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-timeoutCtx.Done():
		return timeoutCtx.Err()
	}
}

// StartFSDServer 启动FSD服务器
func StartFSDServer(applicationContent *ApplicationContent) {
	config := applicationContent.ConfigManager().Config()
	logger := applicationContent.Logger().FsdLogger()

	serverName := "FSD"
	if *global.Vatsim {
		if *global.VatsimFull && config.Server.General.SimulatorServer {
			serverName = "VATSIM SWEATBOX FSD"
		} else {
			serverName = "VATSIM FSD"
		}
	}

	sem := make(chan struct{}, config.Server.FSDServer.MaxWorkers)
	ln, err := net.Listen("tcp", config.Server.FSDServer.Address)
	if err != nil {
		logger.FatalF("%s Server Start error: %v", serverName, err)
		return
	}
	logger.InfoF("%s Server Listen On %s", serverName, ln.Addr().String())

	defer func() {
		err := ln.Close()
		if err != nil {
			logger.ErrorF("Server close error: %v", err)
		}
	}()

	applicationContent.Cleaner().Add(NewShutdownCallback(applicationContent.ClientManager()))

	commandContent := command.NewCommandContent(logger, applicationContent)
	commandHandler := command.NewCommandHandler()

	if *global.VisualPilot {
		commandHandler.Register(fsd.VisualPilotPeriodic, commandContent.HandleClientIdent, nil)
		commandHandler.Register(fsd.VisualPilotPosUpdate, commandContent.HandleClientIdent, nil)
		commandHandler.Register(fsd.VisualPilotStop, commandContent.HandleClientIdent, nil)
	}
	commandHandler.Register(fsd.PilotPosition, commandContent.HandlePilotPosUpdate, &fsd.CommandRequirement{RequireLength: 10, Fatal: false})
	commandHandler.Register(fsd.AtcPosition, commandContent.HandleAtcPosUpdate, &fsd.CommandRequirement{RequireLength: 8, Fatal: false})
	commandHandler.Register(fsd.AtcSubVisPoint, commandContent.HandleAtcVisPointUpdate, &fsd.CommandRequirement{RequireLength: 4, Fatal: false})
	commandHandler.Register(fsd.Message, commandContent.HandleMessage, &fsd.CommandRequirement{RequireLength: 3, Fatal: false})
	commandHandler.Register(fsd.ClientQuery, commandContent.HandleClientQuery, &fsd.CommandRequirement{RequireLength: 3, Fatal: false})
	commandHandler.Register(fsd.ClientResponse, commandContent.HandleClientResponse, &fsd.CommandRequirement{RequireLength: 3, Fatal: false})
	commandHandler.Register(fsd.WeatherQuery, commandContent.HandleWeatherQuery, &fsd.CommandRequirement{RequireLength: 4, Fatal: false})
	commandHandler.Register(fsd.Plan, commandContent.HandlePlan, &fsd.CommandRequirement{RequireLength: 17, Fatal: false})
	commandHandler.Register(fsd.AtcEditPlan, commandContent.HandleAtcEditPlan, &fsd.CommandRequirement{RequireLength: 18, Fatal: false})
	commandHandler.Register(fsd.RequestHandoff, commandContent.HandleRequest, &fsd.CommandRequirement{RequireLength: 3, Fatal: false})
	commandHandler.Register(fsd.AcceptHandoff, commandContent.HandleRequest, &fsd.CommandRequirement{RequireLength: 3, Fatal: false})
	commandHandler.Register(fsd.ProController, commandContent.HandleRequest, &fsd.CommandRequirement{RequireLength: 3, Fatal: false})
	commandHandler.Register(fsd.SquawkBox, commandContent.HandleSquawkBox, &fsd.CommandRequirement{RequireLength: 2, Fatal: false})
	if *global.Vatsim {
		commandHandler.Register(fsd.AddAtc, commandContent.HandleVatsimAddAtc, &fsd.CommandRequirement{RequireLength: 7, Fatal: true})
	} else {
		commandHandler.Register(fsd.AddAtc, commandContent.HandleFsdAddAtc, &fsd.CommandRequirement{RequireLength: 12, Fatal: true})
	}
	if *global.VatsimFull {
		commandHandler.Register(fsd.AddPilot, commandContent.HandleVatsimAddPilot, &fsd.CommandRequirement{RequireLength: 8, Fatal: true})
	} else {
		commandHandler.Register(fsd.AddPilot, commandContent.HandleFsdAddPilot, &fsd.CommandRequirement{RequireLength: 8, Fatal: true})
	}
	commandHandler.Register(fsd.RemoveAtc, commandContent.RemoveClient, nil)
	commandHandler.Register(fsd.RemovePilot, commandContent.RemoveClient, nil)
	commandHandler.Register(fsd.KillClient, commandContent.HandleKillClient, &fsd.CommandRequirement{RequireLength: 2, Fatal: false})
	if *global.Vatsim {
		commandHandler.Register(fsd.ClientIdent, commandContent.HandleClientIdent, nil)
	}

	commandHandler.GeneratePossibleCommands()

	sessionContent := packet.NewSessionContent(
		logger,
		commandHandler,
		applicationContent.ClientManager(),
		config.Server.FSDServer.HeartbeatDuration,
		config.Server.General.SimulatorServer,
	)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.ErrorF("Accept connection error: %v", err)
			continue
		}

		logger.DebugF("Accepted new connection from %s", conn.RemoteAddr().String())

		sem <- struct{}{}
		go func(c net.Conn) {
			session := packet.NewSession(conn)
			sessionContent.HandleConnection(session)
			<-sem
		}(conn)
	}
}
