// Package fsd
package fsd

import "time"

type Position struct {
	Latitude   float64
	Longitude  float64
	LastUpdate time.Time
}

func (p *Position) PositionValid() bool {
	return p.Latitude != 0 && p.Longitude != 0
}

func (p *Position) SetPosition(latitude, longitude float64) {
	p.Latitude = latitude
	p.Longitude = longitude
	p.LastUpdate = time.Now()
}

func (p *Position) ResetPosition() {
	p.Latitude = 0
	p.Longitude = 0
	p.LastUpdate = time.Time{}
}
