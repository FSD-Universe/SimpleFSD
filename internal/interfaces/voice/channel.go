// Package voice
package voice

import (
	"sync"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
)

type ChannelFrequency int

const (
	UNICOM    ChannelFrequency = 122800
	EMERGENCY ChannelFrequency = 121500
)

type Channel struct {
	Frequency    ChannelFrequency
	Controller   fsd.ClientInterface
	ClientsMutex sync.RWMutex
	Clients      map[int]*Transmitter
	CreatedAt    time.Time
}
