// Package fsd
package fsd

import (
	"context"
	"errors"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
)

var (
	ErrCallsignNotFound = errors.New("callsign not found")
	ErrCidMissMatch     = errors.New("cid miss match")
)

type ClientManagerInterface interface {
	GetWhazzupCacheTime() time.Duration
	GetWhazzupContent() *OnlineClients
	Shutdown(ctx context.Context) error
	GetClientSnapshot() []ClientInterface
	AddClient(client ClientInterface) error
	GetClient(callsign string) (ClientInterface, bool)
	DeleteClient(callsign string) bool
	HandleKickClientFromServerMessage(message *queue.Message) error
	HandleSendMessageToClientMessage(message *queue.Message) error
	HandleBroadcastMessage(message *queue.Message) error
	KickClientFromServer(callsign string, reason string) (ClientInterface, error)
	SendMessageTo(callsign string, message []byte) error
	BroadcastMessage(message []byte, fromClient ClientInterface, filter BroadcastFilter)
}

type BroadcastMessageData struct {
	From    string
	Target  BroadcastTarget
	Message string
}

type LockChange struct {
	TargetCallsign string
	TargetCid      int
	Locked         bool
}

type FlushFlightPlan struct {
	TargetCallsign string
	TargetCid      int
	FlightPlan     *operation.FlightPlan
}

type SendRawMessageData struct {
	From    string
	To      string
	Message string
}

type KickClientData struct {
	Callsign string
	Reason   string
}

type OnlineGeneral struct {
	Version          int    `json:"version"`
	GenerateTime     string `json:"generate_time"`
	ConnectedClients int    `json:"connected_clients"`
	OnlinePilot      int    `json:"online_pilot"`
	OnlineController int    `json:"online_controller"`
}

type OnlinePilot struct {
	Cid         int                   `json:"cid"`
	Callsign    string                `json:"callsign"`
	RealName    string                `json:"real_name"`
	Latitude    float64               `json:"latitude"`
	Longitude   float64               `json:"longitude"`
	Transponder string                `json:"transponder"`
	Pitch       float64               `json:"pitch"`
	Bank        float64               `json:"bank"`
	Hdg         float64               `json:"hdg"`
	Heading     int                   `json:"heading"`
	OnGround    bool                  `json:"on_ground"`
	VoiceRange  float64               `json:"voice_range"`
	Altitude    int                   `json:"altitude"`
	GroundSpeed int                   `json:"ground_speed"`
	FlightPlan  *operation.FlightPlan `json:"flight_plan"`
	LogonTime   string                `json:"logon_time"`
}

func NewOnlinePilotFromClient(client ClientInterface) *OnlinePilot {
	onlinePilot := &OnlinePilot{
		Cid:         client.User().Cid,
		Callsign:    client.Callsign(),
		RealName:    client.RealName(),
		Latitude:    client.Position()[0].Latitude,
		Longitude:   client.Position()[0].Longitude,
		Transponder: client.Transponder(),
		VoiceRange:  client.VoiceRange(),
		Altitude:    client.Altitude(),
		GroundSpeed: client.GroundSpeed(),
		FlightPlan:  client.FlightPlan(),
		LogonTime:   client.History().StartTime.Format(time.RFC3339),
	}
	onlinePilot.Pitch, onlinePilot.Bank, onlinePilot.Hdg, onlinePilot.OnGround = client.Posture()
	onlinePilot.Heading = int(onlinePilot.Hdg)
	return onlinePilot
}

type OnlineController struct {
	Cid           int      `json:"cid"`
	Callsign      string   `json:"callsign"`
	RealName      string   `json:"real_name"`
	Latitude      float64  `json:"latitude"`
	Longitude     float64  `json:"longitude"`
	Rating        int      `json:"rating"`
	RatingLabel   string   `json:"rating_label"`
	Facility      int      `json:"facility"`
	FacilityLabel string   `json:"facility_label"`
	Frequency     int      `json:"frequency"`
	Range         int      `json:"range"`
	VoiceRange    float64  `json:"voice_range"`
	OfflineTime   string   `json:"offline_time"`
	IsBreak       bool     `json:"is_break"`
	AtcInfo       []string `json:"atc_info"`
	LogonTime     string   `json:"logon_time"`
}

func NewOnlineControllerFromClient(client ClientInterface) *OnlineController {
	return &OnlineController{
		Cid:           client.User().Cid,
		Callsign:      client.Callsign(),
		RealName:      client.RealName(),
		Latitude:      client.Position()[0].Latitude,
		Longitude:     client.Position()[0].Longitude,
		Rating:        client.Rating().Index(),
		RatingLabel:   client.Rating().String(),
		Facility:      client.Facility().Index(),
		FacilityLabel: client.Facility().String(),
		Frequency:     client.Frequency() + 100000,
		Range:         int(client.VisualRange()),
		VoiceRange:    client.VoiceRange(),
		OfflineTime:   client.LogoffTime(),
		IsBreak:       client.IsBreak(),
		AtcInfo:       client.AtisInfo(),
		LogonTime:     client.History().StartTime.Format(time.RFC3339),
	}
}

type OnlineClients struct {
	General     OnlineGeneral       `json:"general"`
	Pilots      []*OnlinePilot      `json:"pilots"`
	Controllers []*OnlineController `json:"controllers"`
}
