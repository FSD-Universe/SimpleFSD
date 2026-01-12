// Package fsd
package fsd

import (
	"errors"

	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
)

type Callback func()

type PilotPath struct {
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Altitude    int     `json:"altitude"`
	GroundSpeed int     `json:"ground_speed"`
	Timestamp   int64   `json:"timestamp"`
}

var (
	ErrClientDisconnected = errors.New("client disconnected")
	ErrClientSocketWrite  = errors.New("client socket write error")
)

type ClientInterface interface {
	Disconnected() bool
	Delete()
	Reconnect(socket SessionInterface) bool
	MarkedDisconnect(immediate bool)
	UpsertFlightPlan(flightPlanData []string) error
	SetPosition(index int, lat float64, lon float64) error
	UpdatePilotPos(transponder int, lat float64, lon float64, alt int, groundSpeed int, pbh uint32)
	UpdateAtcPos(frequency int, facility Facility, visualRange float64, lat float64, lon float64)
	UpdateAtcVisPoint(visIndex int, lat float64, lon float64) error
	ClearAtcAtisInfo()
	AddAtcAtisInfo(atisInfo string)
	SendError(result *Result)
	SendLineWithoutLog(line []byte) error
	SendLine(line []byte)
	SendMotd()
	UpdateCapacities(capacities []string)
	CheckCapacity(capacity string) bool
	CheckFacility(facility Facility) bool
	CheckRating(rating []Rating) bool
	IsAtc() bool
	IsAtis() bool
	Callsign() string
	Rating() Rating
	Facility() Facility
	RealName() string
	Position() [4]Position
	VisualRange() float64
	VoiceRange() float64
	SetUser(user *operation.User)
	SetSimType(simType int)
	FlightPlan() *operation.FlightPlan
	User() *operation.User
	Frequency() int
	AtisInfo() []string
	History() *operation.History
	Transponder() string
	Altitude() int
	GroundSpeed() int
	Posture() (float64, float64, float64, bool)
	Paths() []*PilotPath
	LogoffTime() string
	SetLogoffTime(time string)
	IsBreak() bool
	SetBreak(isBreak bool)
	SetRating(rating Rating)
	SetRealName(realName string)
	ClearFlightPlan()
	SetFlightPlan(flightPlan *operation.FlightPlan)
	SetDeleteCallback(deleteCallback Callback)
	SetDisconnectCallback(disconnectCallback Callback)
	SetReconnectCallback(reconnectCallback Callback)
	SetMessageReceivedCallback(messageReceivedCallback func([]byte))
}
