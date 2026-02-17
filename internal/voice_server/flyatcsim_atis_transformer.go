// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package voice_server
package voice_server

import (
	"regexp"
	"strings"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/voice"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

const (
	sep   = ", "
	space = " "
)

var (
	runwayReg      = regexp.MustCompile(`^\d{2}[LRC]?$`)
	timeReg        = regexp.MustCompile(`^\d{4}Z$`)
	windReg        = regexp.MustCompile(`^(\d{3}V\d{3}|WIND|GUST)\b`)
	rvrReg         = regexp.MustCompile(`\b\d{1,4}M\b`)
	depArrReg      = regexp.MustCompile(`^(DEPARTURE|EXPECT)\b`)
	cloudReg       = regexp.MustCompile(`^(FEW|SCT|BKN|OVC)\b`)
	visReg         = regexp.MustCompile(`^(VIS|AT)\b`)
	temperatureReg = regexp.MustCompile(`^(TEMP|DEW)\b`)
	numReg         = regexp.MustCompile(`\b\d+\b`)
)

type FASAtisTransformer struct {
	airports map[string]*config.AirportData
}

func NewFASAtisTransformer(airports map[string]*config.AirportData) *FASAtisTransformer {
	return &FASAtisTransformer{airports: airports}
}

// ZSSS DEP & ARR ATIS A
func (transform *FASAtisTransformer) parseFirstLine(atis *voice.ATIS, line string) bool {
	parts := strings.Split(line, space)
	icao := parts[0]
	airport, ok := transform.airports[icao]
	if !ok {
		return false
	}
	atis.AirportName = airport.Name
	atis.Letter = parts[len(parts)-1]
	if len(parts) > 4 {
		atis.Type = voice.ATISTypeBoth
	} else if parts[1] == "DEP" {
		atis.Type = voice.ATISTypeDeparture
	} else if parts[1] == "ARR" {
		atis.Type = voice.ATISTypeArrival
	}
	return true
}

// DEPARTURE RWY 36L, EXPECT ILS APPROACH RWY 36R
func (transform *FASAtisTransformer) parseDepartureAndArrivalLine(atis *voice.ATIS, line string) {
	parts := strings.Split(line, space)
	if parts[0] == "DEPARTURE" {
		utils.ForEach(parts[2:], func(_ int, part string) {
			if runwayReg.MatchString(part) {
				atis.Departure.Runways = append(atis.Departure.Runways, part)
			}
		})
	} else if parts[0] == "EXPECT" {
		switch parts[1] {
		case "ILS":
			atis.Arrival.ApproachType = voice.ATISApproachTypeILS
		case "RNP":
			atis.Arrival.ApproachType = voice.ATISApproachTypeRNP
		case "VOR":
			atis.Arrival.ApproachType = voice.ATISApproachTypeVOR
		case "VISUAL":
			atis.Arrival.ApproachType = voice.ATISApproachTypeVisual
		}
		utils.ForEach(parts[4:], func(_ int, part string) {
			if runwayReg.MatchString(part) {
				atis.Arrival.Runways = append(atis.Arrival.Runways, part)
			}
		})
	}
}

// WIND 060 DEG 07 MPS, GUST 15 MPS, 010V100 DEG
func (transform *FASAtisTransformer) parseWind(atis *voice.ATIS, line string) {
	parts := strings.Split(line, space)
	atis.Wind.Unit = voice.ATISUnitMetric
	if parts[0] == "WIND" {
		atis.Wind.Direction = utils.StrToInt(parts[1], 0)
		atis.Wind.Speed = utils.StrToInt(parts[3], 0)
		if atis.Wind.Direction == 0 && atis.Wind.Speed == 0 {
			atis.Wind.Calm = true
		} else if atis.Wind.Direction == 0 {
			atis.Wind.Variable = true
		}
	} else if parts[0] == "GUST" {
		atis.Wind.Gust = utils.StrToInt(parts[1], 0)
	} else if windReg.MatchString(line) {
		w := strings.Split(parts[0], "V")
		atis.Wind.Change = true
		atis.Wind.ChangeFrom = utils.StrToInt(w[0], 0)
		atis.Wind.ChangeTo = utils.StrToInt(w[1], 0)
	}
}

// VIS 7000 M, AT NORTH | VIS MORE THAN 10 KM
func (transform *FASAtisTransformer) parseVisibility(atis *voice.ATIS, line string) {
	parts := strings.Split(line, space)
	if parts[0] == "VIS" {
		if len(parts) > 3 {
			atis.Visibility.Visibility = 10000
		} else {
			atis.Visibility.Visibility = utils.StrToInt(parts[1], 0)
		}
	} else if parts[0] == "AT" {
		atis.Visibility.Direction = parts[1]
	}
}

// RVR RWY 36L MORE THAN 4000M | RVR RWY 36L BETWEEN 2000M AND 4000M NC
func (transform *FASAtisTransformer) parseRVR(atis *voice.ATIS, line string) {
	parts := strings.Split(line, space)
	if parts[0] == "RVR" {
		rvr := &voice.ATISRunwayVisualRange{Runway: parts[2]}
		nums := rvrReg.FindAllString(line, -1)
		if parts[4] == "THAN" {
			switch parts[3] {
			case "MORE":
				rvr.OverRange = voice.ATISRVROverRangeTypeUp
			case "LESS":
				rvr.OverRange = voice.ATISRVROverRangeTypeDown
			}
		} else {
			rvr.OverRange = voice.ATISRVROverRangeTypeNone
		}
		if len(nums) == 1 {
			rvr.LowVisibility = utils.StrToInt(strings.TrimSuffix(nums[0], "M"), 0)
			rvr.HighVisibility = rvr.LowVisibility
		} else if len(nums) == 2 {
			rvr.LowVisibility = utils.StrToInt(strings.TrimSuffix(nums[0], "M"), 0)
			rvr.HighVisibility = utils.StrToInt(strings.TrimSuffix(nums[1], "M"), 0)
		}
		if strings.HasSuffix(line, "NC") {
			rvr.Trend = voice.ATISRVRTrendNone
		} else if strings.HasSuffix(line, "DOWNWARD TNDCY") {
			rvr.Trend = voice.ATISRVRTrendDown
		} else if strings.HasSuffix(line, "UPWARD TNDCY") {
			rvr.Trend = voice.ATISRVRTrendUp
		}
		atis.RunwayVisualRange = append(atis.RunwayVisualRange, rvr)
	}
}

// BKN 420M
func (transform *FASAtisTransformer) parseCloud(atis *voice.ATIS, line string) {
	parts := strings.Split(line, space)
	if len(parts) >= 2 {
		cloud := &voice.ATISCloud{}
		switch parts[0] {
		case "FEW":
			cloud.Coverage = voice.ATISCloudTypeFew
		case "SCT":
			cloud.Coverage = voice.ATISCloudTypeScattered
		case "BKN":
			cloud.Coverage = voice.ATISCloudTypeBroken
		case "OVC":
			cloud.Coverage = voice.ATISCloudTypeOvercast
		}
		cloud.Height = utils.StrToInt(strings.TrimSuffix(parts[1], "M"), 0)
		cloud.Unit = voice.ATISUnitMetric
		atis.Clouds = append(atis.Clouds, cloud)
	}
}

// TEMP 10, DEW POINT 05
func (transform *FASAtisTransformer) parseTemperature(atis *voice.ATIS, line string) {
	parts := strings.Split(line, space)
	if parts[0] == "TEMP" {
		atis.Temperature.Temperature = utils.StrToInt(parts[1], 0)
	} else if parts[0] == "DEW" {
		atis.Temperature.Dewpoint = utils.StrToInt(parts[2], 0)
	}
}

// QNH 1023 HPA
func (transform *FASAtisTransformer) parseQNH(atis *voice.ATIS, line string) {
	parts := strings.Split(line, space)
	if parts[0] == "QNH" {
		atis.QNH = utils.StrToInt(parts[1], 0)
	}
}

// TRANSITION LEVEL 3600 M AND TRANSITION ALTITUDE 3000 M RPT RECEIPT OF ATIS A ON ZSSS
func (transform *FASAtisTransformer) parseTransition(atis *voice.ATIS, line string) {
	nums := numReg.FindAllString(line, -1)
	if len(nums) == 2 {
		atis.TransitionLevel = utils.StrToInt(nums[0], 0)
		atis.TransitionAltitude = utils.StrToInt(nums[1], 0)
	} else {
		if atis.Type == voice.ATISTypeArrival {
			atis.TransitionLevel = utils.StrToInt(nums[0], 0)
		} else {
			atis.TransitionAltitude = utils.StrToInt(nums[0], 0)
		}
	}
}

func (transform *FASAtisTransformer) Transform(text string) *voice.ATIS {
	if text == "" {
		return nil
	}
	text = strings.ToUpper(text)
	lines := strings.Split(text, sep)
	atis := voice.NewATIS()
	transform.parseFirstLine(atis, lines[0])
	for _, line := range lines[1:] {
		if depArrReg.MatchString(line) {
			transform.parseDepartureAndArrivalLine(atis, line)
		}
		if timeReg.MatchString(line) {
			atis.Time = line[:4]
		}
		if windReg.MatchString(line) {
			transform.parseWind(atis, line)
		}
		if visReg.MatchString(line) {
			transform.parseVisibility(atis, line)
		}
		if cloudReg.MatchString(line) {
			transform.parseCloud(atis, line)
		}
		if temperatureReg.MatchString(line) {
			transform.parseTemperature(atis, line)
		}
		if strings.HasPrefix(line, "RVR") {
			transform.parseRVR(atis, line)
		}
		if strings.HasPrefix(line, "QNH") {
			transform.parseQNH(atis, line)
		}
		if strings.HasPrefix(line, "TRANSITION") {
			transform.parseTransition(atis, line)
		}
		if line == "NOSIG" {
			atis.NoSig = true
		}
	}
	return atis
}
