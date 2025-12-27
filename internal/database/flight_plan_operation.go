package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/utils"
	"gorm.io/gorm"
)

type FlightPlanOperation struct {
	logger       log.LoggerInterface
	config       *config.GeneralConfig
	db           *gorm.DB
	queryTimeout time.Duration
}

func NewFlightPlanOperation(logger log.LoggerInterface, db *gorm.DB, queryTimeout time.Duration, config *config.GeneralConfig) *FlightPlanOperation {
	return &FlightPlanOperation{logger: logger, config: config, db: db, queryTimeout: queryTimeout}
}

func (flightPlanOperation *FlightPlanOperation) GetFlightPlanByCid(cid int) (flightPlan *FlightPlan, err error) {
	if flightPlanOperation.config.SimulatorServer {
		return nil, ErrSimulatorServer
	}
	flightPlan = &FlightPlan{}
	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()
	err = flightPlanOperation.db.WithContext(ctx).Where("cid = ?", cid).First(flightPlan).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrFlightPlanNotFound
		}
		return nil, err
	}
	return
}

func (flightPlanOperation *FlightPlanOperation) UpsertFlightPlan(user *User, callsign string, flightPlanData []string) (flightPlan *FlightPlan, err error) {
	if len(flightPlanData) < 17 {
		return nil, ErrFlightPlanDataTooShort
	}
	// 再次检查一遍防止重复创建
	flightPlan, err = flightPlanOperation.GetFlightPlanByCid(user.Cid)
	if err != nil {
		flightPlan = &FlightPlan{
			Cid:      user.Cid,
			Callsign: callsign,
			Locked:   false,
			FromWeb:  false,
		}
	}
	flightPlan.Callsign = callsign
	flightPlanOperation.UpdateFlightPlanData(flightPlan, flightPlanData)
	// 模拟机服务器就不用写数据库了, 直接返回
	if flightPlanOperation.config.SimulatorServer {
		return flightPlan, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()
	err = flightPlanOperation.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Save(flightPlan).Error; errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrFlightPlanExists
		} else if err != nil {
			return err
		}
		return nil
	})
	return
}

func (flightPlanOperation *FlightPlanOperation) UpdateFlightPlanData(flightPlan *FlightPlan, flightPlanData []string) {
	flightPlan.FlightType = flightPlanData[2]
	flightPlan.AircraftType = flightPlanData[3]
	flightPlan.Tas = utils.StrToInt(flightPlanData[4], 100)
	flightPlan.DepartureAirport = flightPlanData[5]
	flightPlan.DepartureTime = utils.StrToInt(flightPlanData[6], 0)
	flightPlan.AtcDepartureTime = utils.StrToInt(flightPlanData[7], 0)
	flightPlan.CruiseAltitude = flightPlanData[8]
	flightPlan.ArrivalAirport = flightPlanData[9]
	flightPlan.RouteTimeHour = flightPlanData[10]
	flightPlan.RouteTimeMinute = flightPlanData[11]
	flightPlan.FuelTimeHour = flightPlanData[12]
	flightPlan.FuelTimeMinute = flightPlanData[13]
	flightPlan.AlternateAirport = flightPlanData[14]
	flightPlan.Remarks = flightPlanData[15]
	flightPlan.Route = flightPlanData[16]
}

func (flightPlanOperation *FlightPlanOperation) UpdateFlightPlan(flightPlan *FlightPlan, flightPlanData []string, atcEdit bool) (err error) {
	if len(flightPlanData) < 17 {
		return ErrFlightPlanDataTooShort
	}

	if !flightPlanOperation.config.SimulatorServer && !atcEdit && flightPlan.Locked {
		return ErrFlightPlanLocked
	}

	// 模拟机服务器只用更新内存中数据就行
	flightPlanOperation.UpdateFlightPlanData(flightPlan, flightPlanData)
	if flightPlanOperation.config.SimulatorServer {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()

	return flightPlanOperation.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Save(flightPlan).Error
	})
}

func (flightPlanOperation *FlightPlanOperation) SaveFlightPlan(flightPlan *FlightPlan) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()
	return flightPlanOperation.db.WithContext(ctx).Save(flightPlan).Error
}

func (flightPlanOperation *FlightPlanOperation) GetFlightPlans(page, pageSize int) (flightPlans []*FlightPlan, total int64, err error) {
	flightPlans = make([]*FlightPlan, 0, pageSize)
	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()
	flightPlanOperation.db.WithContext(ctx).Model(&FlightPlan{}).Select("id").Count(&total)
	err = flightPlanOperation.db.WithContext(ctx).Offset((page - 1) * pageSize).Order("cid").Limit(pageSize).Find(&flightPlans).Error
	return
}

func (flightPlanOperation *FlightPlanOperation) LockFlightPlan(flightPlan *FlightPlan) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()
	return flightPlanOperation.db.WithContext(ctx).Model(flightPlan).Updates(&FlightPlan{Locked: true}).Error
}

func (flightPlanOperation *FlightPlanOperation) UnlockFlightPlan(flightPlan *FlightPlan) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()
	return flightPlanOperation.db.WithContext(ctx).Model(flightPlan).Select("locked").Updates(&FlightPlan{Locked: false}).Error
}

func (flightPlanOperation *FlightPlanOperation) DeleteSelfFlightPlan(flightPlan *FlightPlan) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()
	return flightPlanOperation.db.WithContext(ctx).Delete(flightPlan).Where("locked = ?", false).Error
}

func (flightPlanOperation *FlightPlanOperation) DeleteFlightPlan(flightPlan *FlightPlan) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()
	result := flightPlanOperation.db.WithContext(ctx).Delete(flightPlan)
	if result.RowsAffected == 0 {
		return ErrFlightPlanNotFound
	}
	return result.Error
}

func (flightPlanOperation *FlightPlanOperation) UpdateCruiseAltitude(flightPlan *FlightPlan, cruiseAltitude string) (err error) {
	flightPlan.CruiseAltitude = cruiseAltitude

	if flightPlanOperation.config.SimulatorServer {
		return nil
	}

	flightPlan.Locked = true

	ctx, cancel := context.WithTimeout(context.Background(), flightPlanOperation.queryTimeout)
	defer cancel()

	result := flightPlanOperation.db.WithContext(ctx).Model(flightPlan).Updates(map[string]interface{}{
		"cruise_altitude": cruiseAltitude,
		"locked":          true,
	})

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrFlightPlanNotFound
		}
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrFlightPlanLocked
	}
	return nil
}

func (flightPlanOperation *FlightPlanOperation) ToString(flightPlan *FlightPlan) string {
	return fmt.Sprintf("$FP%s:%s:%s:%s:%d:%s:%d:%d:%s:%s:%d:%d:%d:%d:%s:%s:%s\r\n",
		flightPlan.Callsign, fsd.AllATC, flightPlan.FlightType, flightPlan.AircraftType, flightPlan.Tas,
		flightPlan.DepartureAirport, flightPlan.DepartureTime, flightPlan.AtcDepartureTime, flightPlan.CruiseAltitude,
		flightPlan.ArrivalAirport, utils.StrToInt(flightPlan.RouteTimeHour, 0),
		utils.StrToInt(flightPlan.RouteTimeMinute, 0), utils.StrToInt(flightPlan.FuelTimeHour, 0),
		utils.StrToInt(flightPlan.FuelTimeMinute, 0), flightPlan.AlternateAirport, flightPlan.Remarks, flightPlan.Route)
}
