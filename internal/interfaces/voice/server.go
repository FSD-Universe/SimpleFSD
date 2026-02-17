// Package voice
package voice

import "github.com/half-nothing/simple-fsd/internal/interfaces/fsd"

type VoicePacket struct {
	Cid         int
	Transmitter int
	Frequency   int
	Callsign    string
	Data        []byte
	RawData     []byte
}

func NewVoicePacket() *VoicePacket {
	return &VoicePacket{
		Cid:         0,
		Transmitter: 0,
		Frequency:   0,
		Callsign:    "",
		Data:        nil,
		RawData:     nil,
	}
}

type ServerInterface interface {
	Start() error
	Stop()
	ATISOffline(client fsd.ClientInterface)
	ATISUpdate(client fsd.ClientInterface, letter string)
}
