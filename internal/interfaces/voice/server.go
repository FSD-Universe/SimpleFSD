// Package voice
package voice

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

type VoiceServerInterface interface {
	Start() error
	Stop()
}
