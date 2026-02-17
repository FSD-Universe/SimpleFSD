// Package config
package config

import (
	"errors"

	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
)

type AirportData struct {
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
	Elev  float64 `json:"elev"`
	Range float64 `json:"range"`
	Name  string  `json:"name"`
}

func (config *AirportData) checkValid(_ log.LoggerInterface) *ValidResult {
	if config.Range <= 0 {
		return ValidFail(errors.New("airport_range must be greater than zero"))
	}
	return ValidPass()
}
