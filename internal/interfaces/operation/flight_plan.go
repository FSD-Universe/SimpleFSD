// Package operation
package operation

import (
	"errors"
	"time"
)

type FlightPlan struct {
	ID               uint      `gorm:"primarykey" json:"id"`
	Cid              int       `gorm:"uniqueIndex;not null" json:"cid"`
	Callsign         string    `gorm:"size:16;index;not null" json:"callsign"`
	FlightType       string    `gorm:"size:4;not null" json:"flight_rules"`
	AircraftType     string    `gorm:"size:128;not null" json:"aircraft"`
	Tas              int       `gorm:"not null" json:"cruise_tas"`
	DepartureAirport string    `gorm:"size:4;not null" json:"departure"`
	DepartureTime    int       `gorm:"not null" json:"departure_time"`
	AtcDepartureTime int       `gorm:"not null" json:"-"`
	CruiseAltitude   string    `gorm:"size:8;not null" json:"altitude"`
	ArrivalAirport   string    `gorm:"size:4;not null" json:"arrival"`
	RouteTimeHour    string    `gorm:"size:2;not null" json:"route_time_hour"`
	RouteTimeMinute  string    `gorm:"size:2;not null" json:"route_time_minute"`
	FuelTimeHour     string    `gorm:"size:2;not null" json:"fuel_time_hour"`
	FuelTimeMinute   string    `gorm:"size:2;not null" json:"fuel_time_minute"`
	AlternateAirport string    `gorm:"size:4;not null" json:"alternate"`
	Remarks          string    `gorm:"type:text;not null" json:"remarks"`
	Route            string    `gorm:"type:text;not null" json:"route"`
	Locked           bool      `gorm:"default:0;not null" json:"locked"`
	FromWeb          bool      `gorm:"default:0;not null" json:"from_web"`
	CreatedAt        time.Time `json:"-"`
	UpdatedAt        time.Time `json:"-"`
}

var (
	ErrFlightPlanNotFound     = errors.New("flight plan not found")
	ErrSimulatorServer        = errors.New("simulator server not support flight plan store")
	ErrFlightPlanDataTooShort = errors.New("flight plan data is too short")
	ErrFlightPlanExists       = errors.New("flight plan already exists")
	ErrFlightPlanLocked       = errors.New("flight plan locked")
)

// FlightPlanOperationInterface 飞行计划操作接口定义
type FlightPlanOperationInterface interface {
	// GetFlightPlanByCid 通过用户cid获取飞行计划, 当err为nil时返回值flightPlan有效
	GetFlightPlanByCid(cid int) (flightPlan *FlightPlan, err error)
	// UpsertFlightPlan 创建或更新飞行计划, 当err为nil时返回值flightPlan有效
	UpsertFlightPlan(user *User, callsign string, flightPlanData []string) (flightPlan *FlightPlan, err error)
	// UpdateFlightPlanData 更新飞行计划(不提交数据库)
	UpdateFlightPlanData(flightPlan *FlightPlan, flightPlanData []string)
	// UpdateFlightPlan 更新飞行计划(提交数据库), 当err为nil时更新成功
	UpdateFlightPlan(flightPlan *FlightPlan, flightPlanData []string, atcEdit bool) (err error)
	SaveFlightPlan(flightPlan *FlightPlan) (err error)
	GetFlightPlans(page, pageSize int) (flightPlans []*FlightPlan, total int64, err error)
	LockFlightPlan(flightPlan *FlightPlan) (err error)
	UnlockFlightPlan(flightPlan *FlightPlan) (err error)
	DeleteSelfFlightPlan(flightPlan *FlightPlan) (err error)
	DeleteFlightPlan(flightPlan *FlightPlan) (err error)
	// UpdateCruiseAltitude 更新巡航高度, 当err为nil时更新成功
	UpdateCruiseAltitude(flightPlan *FlightPlan, cruiseAltitude string) (err error)
	// ToString 将飞行计划转换为ES和Swift可识别的形式
	ToString(flightPlan *FlightPlan) (str string)
}
