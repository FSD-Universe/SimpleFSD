// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package voice_server
package atis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/half-nothing/simple-fsd/internal/interfaces/voice"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type EnglishAtisGenerator struct {
}

func (gen *EnglishAtisGenerator) formatRunway(runway string) string {
	words := make([]string, len(runway))
	utils.ForEach([]rune(runway), func(i int, c rune) {
		if word, ok := voice.ICAODigitsMap[string(c)]; ok {
			words[i] = word
			return
		}
		switch c {
		case 'L':
			words[i] = "left"
		case 'R':
			words[i] = "right"
		case 'C':
			words[i] = "center"
		}
	})
	return strings.Join(words, space)
}

func (gen *EnglishAtisGenerator) formatNumber(number string) string {
	words := make([]string, len(number))
	utils.ForEach([]rune(number), func(i int, c rune) {
		if c == '-' {
			words[i] = "minus"
			return
		}
		if word, ok := voice.ICAODigitsMap[string(c)]; ok {
			words[i] = word
			return
		}
	})
	return strings.Join(words, space)
}

func (gen *EnglishAtisGenerator) formatMetricAltitude(number int) string {
	words := make([]string, 0)
	if number >= 1000 {
		words = append(words, gen.formatNumber(strconv.Itoa(number/1000)), "thousand")
	}
	if number%1000 >= 100 {
		words = append(words, voice.ICAODigitsMap[strconv.Itoa(number%1000/100)], "hundred")
	}
	words = append(words, "meter")
	return strings.Join(words, space)
}

func (gen *EnglishAtisGenerator) formatImperialAltitude(number int) string {
	words := make([]string, 0)
	if number >= 1000 {
		words = append(words, gen.formatNumber(strconv.Itoa(number/1000)), "thousand")
	}
	if number%1000 >= 100 {
		words = append(words, voice.ICAODigitsMap[strconv.Itoa(number%1000/100)], "hundred")
	}
	words = append(words, "feet")
	return strings.Join(words, space)
}

func (gen *EnglishAtisGenerator) Generate(atis *voice.ATIS) string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("%s information %s,", atis.AirportName, voice.ICAOLettersMap[atis.Letter]))
	for _, c := range atis.Time {
		sb.WriteString(space)
		sb.WriteString(voice.ICAODigitsMap[string(c)])
	}
	sb.WriteString(" U T C")
	if atis.Type == voice.ATISTypeDeparture || atis.Type == voice.ATISTypeBoth {
		sb.WriteString(".departure runway")
		if len(atis.Departure.Runways) > 0 {
			for _, runway := range atis.Departure.Runways[:len(atis.Departure.Runways)-1] {
				sb.WriteString(space)
				sb.WriteString(gen.formatRunway(runway))
				sb.WriteString(" and")
			}
			sb.WriteString(space)
			sb.WriteString(gen.formatRunway(atis.Departure.Runways[len(atis.Departure.Runways)-1]))
		}
	}
	if atis.Type == voice.ATISTypeArrival || atis.Type == voice.ATISTypeBoth {
		sb.WriteString(".expect ")
		switch atis.Arrival.ApproachType {
		case voice.ATISApproachTypeILS:
			sb.WriteString("I L S approach runway")
		case voice.ATISApproachTypeRNP:
			sb.WriteString("R N P approach runway")
		case voice.ATISApproachTypeVOR:
			sb.WriteString("V O R approach runway")
		case voice.ATISApproachTypeVisual:
			sb.WriteString("visual approach runway")
		}
		if len(atis.Arrival.Runways) > 0 {
			for _, runway := range atis.Arrival.Runways[:len(atis.Arrival.Runways)-1] {
				sb.WriteString(space)
				sb.WriteString(gen.formatRunway(runway))
				sb.WriteString(" and")
			}
			sb.WriteString(space)
			sb.WriteString(gen.formatRunway(atis.Arrival.Runways[len(atis.Arrival.Runways)-1]))
		}
	}
	sb.WriteString(". wind ")
	if atis.Wind.Calm {
		sb.WriteString("calm")
	} else {
		if atis.Wind.Variable {
			sb.WriteString("variable ")
		} else {
			sb.WriteString(gen.formatNumber(fmt.Sprintf("%03d", atis.Wind.Direction)))
			sb.WriteString(" degrees ")
		}
		sb.WriteString("at ")
		sb.WriteString(gen.formatNumber(strconv.Itoa(atis.Wind.Speed)))
		if atis.Wind.Unit == voice.ATISUnitMetric {
			sb.WriteString(" meters per second")
		} else {
			sb.WriteString(" knots")
		}
		if atis.Wind.Gust != 0 {
			sb.WriteString(" gust ")
			sb.WriteString(gen.formatNumber(strconv.Itoa(atis.Wind.Gust)))
		}
		if atis.Wind.Change {
			sb.WriteString(", wind varying from ")
			sb.WriteString(gen.formatNumber(fmt.Sprintf("%03d", atis.Wind.ChangeFrom)))
			sb.WriteString(" degrees to ")
			sb.WriteString(gen.formatNumber(fmt.Sprintf("%03d", atis.Wind.ChangeTo)))
			sb.WriteString(" degrees")
		}
	}
	sb.WriteString(", temperature ")
	sb.WriteString(gen.formatNumber(strconv.Itoa(atis.Temperature.Temperature)))
	sb.WriteString(" , dewpoint ")
	sb.WriteString(gen.formatNumber(strconv.Itoa(atis.Temperature.Dewpoint)))
	sb.WriteString(" , Q N H ")
	sb.WriteString(gen.formatNumber(strconv.Itoa(atis.QNH)))
	sb.WriteString(".")
	for _, cloud := range atis.Clouds {
		switch cloud.Coverage {
		case voice.ATISCloudTypeFew:
			sb.WriteString("few")
		case voice.ATISCloudTypeScattered:
			sb.WriteString("scattered")
		case voice.ATISCloudTypeBroken:
			sb.WriteString("broken")
		case voice.ATISCloudTypeOvercast:
			sb.WriteString("overcast")
		}
		sb.WriteString(" cloud in the ")
		switch cloud.Unit {
		case voice.ATISUnitMetric:
			sb.WriteString(gen.formatMetricAltitude(cloud.Height))
		case voice.ATISUnitImperial:
			sb.WriteString(gen.formatImperialAltitude(cloud.Height))
		}
		sb.WriteString(",")
	}
	if len(atis.Clouds) > 0 {
		sb.WriteString(".")
	}
	for _, visibility := range atis.Visibility {
		sb.WriteString("visibility ")
		if visibility.Visibility >= 9999 {
			sb.WriteString("more than ten kilometers")
		} else {
			sb.WriteString(gen.formatMetricAltitude(visibility.Visibility))
		}
		if visibility.Direction != "" {
			sb.WriteString(" AT ")
			sb.WriteString(visibility.Direction)
		}
		sb.WriteString(",")
	}
	if len(atis.Visibility) > 0 {
		sb.WriteString(".")
	}
	for _, visualRange := range atis.RunwayVisualRange {
		sb.WriteString("visual range for runway ")
		sb.WriteString(gen.formatRunway(visualRange.Runway))
		if visualRange.HighVisibility == visualRange.LowVisibility {
			sb.WriteString(" is ")
			switch visualRange.OverRange {
			case voice.ATISRVROverRangeTypeNone:
			case voice.ATISRVROverRangeTypeUp:
				sb.WriteString("more than ")
			case voice.ATISRVROverRangeTypeDown:
				sb.WriteString("less than ")
			}
			sb.WriteString(gen.formatMetricAltitude(visualRange.LowVisibility))
		} else {
			sb.WriteString(" between ")
			sb.WriteString(gen.formatMetricAltitude(visualRange.LowVisibility))
			sb.WriteString(" and ")
			sb.WriteString(gen.formatMetricAltitude(visualRange.HighVisibility))
		}
		switch visualRange.Trend {
		case voice.ATISRVRTrendNone:
		case voice.ATISRVRTrendUp:
			sb.WriteString(" increasing")
		case voice.ATISRVRTrendDown:
			sb.WriteString(" decreasing")
		}
		sb.WriteString(",")
	}
	if len(atis.RunwayVisualRange) > 0 {
		sb.WriteString(".")
	}
	if atis.TransitionLevel != 0 {
		sb.WriteString("transition level is ")
		sb.WriteString(gen.formatMetricAltitude(atis.TransitionLevel))
		sb.WriteString(".")
	}
	if atis.TransitionAltitude != 0 {
		sb.WriteString("transition altitude is ")
		sb.WriteString(gen.formatMetricAltitude(atis.TransitionAltitude))
		sb.WriteString(".")
	}
	sb.WriteString("advice on initial contact you have information ")
	sb.WriteString(voice.ICAOLettersMap[atis.Letter])
	return sb.String()
}
