package database

import (
	"context"
	. "fmt"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type ShutdownCallback struct {
	logger log.LoggerInterface
	db     *gorm.DB
}

func NewShutdownCallback(logger log.LoggerInterface, db *gorm.DB) *ShutdownCallback {
	return &ShutdownCallback{
		logger: logger,
		db:     db,
	}
}

func (dc *ShutdownCallback) Invoke(ctx context.Context) error {
	dc.logger.InfoF("Closing database connection")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := dc.db.DB()
	if err != nil {
		return err
	}
	err = db.Close()
	return err
}

func ConnectDatabase(lg log.LoggerInterface, config *config.Config, debug bool) (*ShutdownCallback, *DatabaseOperations, error) {
	queryTimeout := config.Database.QueryDuration

	connection := config.Database.GetConnection(lg)

	gormConfig := gorm.Config{}
	gormConfig.DefaultTransactionTimeout = 5 * time.Second
	gormConfig.PrepareStmt = true
	gormConfig.TranslateError = true

	if debug {
		gormConfig.Logger = logger.Default.LogMode(logger.Error)
	} else {
		gormConfig.Logger = logger.Default.LogMode(logger.Silent)
	}

	db, err := gorm.Open(connection, &gormConfig)
	if err != nil {
		return nil, nil, Errorf("error occured while connecting to operation: %v", err)
	}

	if err = db.Migrator().AutoMigrate(&User{}, &FlightPlan{}, &History{}, &Activity{}, &ActivityATC{},
		&ActivityPilot{}, &ActivityFacility{}, &AuditLog{}, &ControllerRecord{}, &Ticket{}, &ControllerApplication{}, &Announcement{},
		&OAuth2Client{}, &OAuth2AuthorizationCode{}, &OAuth2Token{}); err != nil {
		return nil, nil, Errorf("error occured while migrating operation: %v", err)
	}

	dbPool, err := db.DB()
	if err != nil {
		return nil, nil, Errorf("error occured while creating operation pool: %v", err)
	}

	maxOpenConnections := config.Database.ServerMaxConnections * 4 / 5 // 不超过数据库最大连接的80%
	maxIdleConnections := maxOpenConnections / 5                       // 空闲连接约为最大连接的20%

	dbPool.SetMaxIdleConns(maxIdleConnections)
	dbPool.SetMaxOpenConns(maxOpenConnections)
	dbPool.SetConnMaxLifetime(config.Database.ConnectIdleDuration)

	err = dbPool.Ping()
	if err != nil {
		return nil, nil, Errorf("error occured while pinging operation: %v", err)
	}
	lg.Info("Database initialized and connection established")

	return NewShutdownCallback(lg, db),
		NewDatabaseOperations(
			NewUserOperation(lg, db, queryTimeout, config.Server.General),
			NewFlightPlanOperation(lg, db, queryTimeout, config.Server.General),
			NewHistoryOperation(lg, db, queryTimeout),
			NewActivityOperation(lg, db, queryTimeout),
			NewAuditLogOperation(lg, db, queryTimeout),
			NewControllerOperation(lg, db, queryTimeout),
			NewControllerRecordOperation(lg, db, queryTimeout),
			NewControllerApplicationOperation(lg, db, queryTimeout),
			NewTicketOperation(lg, db, queryTimeout),
			NewAnnouncementOperation(lg, db, queryTimeout),
			NewOAuth2Operation(lg, db, queryTimeout),
		),
		nil
}
