// Package fsd
package fsd

type ClientError byte

const (
	CommandOk ClientError = iota
	CallsignInUse
	CallsignInvalid
	AlreadyRegistered
	Syntax
	InvalidSrcCallsign
	InvalidCidPassword
	NoCallsignFound
	NoFlightPlan
	NoWeatherProfile
	InvalidProtocolVision
	RequestLevelTooHigh
	ServerFull
	CidSuspended
	InvalidCtrl
	RatingTooLow
	InvalidClient
	AuthTimeout
	Custom
)

var clientErrorsString = []string{"No error", "Callsign in use", "Invalid callsign", "Already registered",
	"Syntax error", "Invalid source callsign", "Invalid CID/password", "No such callsign", "No flightplan",
	"No such weather profile", "Invalid protocol revision", "Requested level too high", "Too many clients connected",
	"CID/PID was suspended", "Not valid control", "Rating too low for this position", "Unauthorized client software",
	"Wrong server type", "Unknown error"}

func (e ClientError) String() string {
	return clientErrorsString[e]
}

func (e ClientError) Index() int {
	return int(e)
}
