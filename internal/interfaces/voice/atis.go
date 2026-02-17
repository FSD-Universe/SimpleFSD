// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package voice
package voice

type ATISType = int

const (
	ATISTypeDeparture ATISType = iota
	ATISTypeArrival
	ATISTypeBoth
)

type ATISUnit = int

const (
	ATISUnitMetric ATISUnit = iota
	ATISUnitImperial
)

type ATISDeparture struct {
	Runways []string
}

type ATISApproachType = int

const (
	ATISApproachTypeILS ATISApproachType = iota
	ATISApproachTypeRNP
	ATISApproachTypeVOR
	ATISApproachTypeVisual
)

type ATISArrival struct {
	Runways      []string
	ApproachType ATISApproachType
}

type ATISWind struct {
	Direction  int
	Speed      int
	Gust       int
	Variable   bool
	Calm       bool
	Change     bool
	ChangeFrom int
	ChangeTo   int
	Unit       ATISUnit
}

type ATISVisibility struct {
	Visibility int
	Direction  string
}

type ATISCloudType = int

const (
	ATISCloudTypeFew ATISCloudType = iota
	ATISCloudTypeScattered
	ATISCloudTypeBroken
	ATISCloudTypeOvercast
)

type ATISCloud struct {
	Coverage ATISCloudType
	Height   int
	Unit     ATISUnit
}

type ATISTemperature struct {
	Temperature int
	Dewpoint    int
}

type ATISRVROverRangeType = int

const (
	ATISRVROverRangeTypeNone ATISRVROverRangeType = iota
	ATISRVROverRangeTypeUp
	ATISRVROverRangeTypeDown
)

type ATISRVRTrend = int

const (
	ATISRVRTrendNone ATISRVRTrend = iota
	ATISRVRTrendUp
	ATISRVRTrendDown
)

type ATISRunwayVisualRange struct {
	Runway         string
	LowVisibility  int
	HighVisibility int
	OverRange      ATISRVROverRangeType
	Trend          ATISRVRTrend
}

type ATIS struct {
	AirportName        string
	Type               ATISType
	Letter             string
	Departure          *ATISDeparture
	Arrival            *ATISArrival
	Time               string
	Wind               *ATISWind
	Visibility         *ATISVisibility
	Temperature        *ATISTemperature
	RunwayVisualRange  []*ATISRunwayVisualRange
	Clouds             []*ATISCloud
	QNH                int
	Altimeter          float64
	TransitionLevel    int
	TransitionAltitude int
	NoSig              bool
	WindShear          []string
}

func NewATIS() *ATIS {
	return &ATIS{
		Departure:         &ATISDeparture{Runways: make([]string, 0)},
		Arrival:           &ATISArrival{Runways: make([]string, 0), ApproachType: ATISApproachTypeILS},
		Wind:              &ATISWind{Unit: ATISUnitMetric},
		Visibility:        &ATISVisibility{},
		Temperature:       &ATISTemperature{},
		RunwayVisualRange: make([]*ATISRunwayVisualRange, 0),
		Clouds:            make([]*ATISCloud, 0),
		WindShear:         make([]string, 0),
	}
}
