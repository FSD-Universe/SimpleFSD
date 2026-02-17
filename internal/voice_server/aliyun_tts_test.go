// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package voice_server
package voice_server

import (
	"os"
	"testing"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
)

func TestAliYunTTS_Synthesize(t *testing.T) {
	airportData := make(map[string]*config.AirportData)
	airportData["ZSSS"] = &config.AirportData{
		Name: "Shanghai Hongqiao International Airport",
	}
	transformer := &FASAtisTransformer{airports: airportData}
	rawAtis := "ZSSS DEP & ARR ATIS A, DEPARTURE RWY 36L, EXPECT ILS APPROACH RWY 36R, 1400Z, WIND 060 DEG 07 MPS, GUST 15 MPS, VIS 7000 M, AT NORTH, 010V100 DEG, RVR RWY 36L MORE THAN 4000M UPWARD TNDCY, RVR RWY 36R BETWEEN 2000M AND 4000M NC, BKN 420M, TEMP 10, DEW POINT 05, QNH 1023 HPA, TRANSITION LEVEL 3600 M AND TRANSITION ALTITUDE 3000 M RPT RECEIPT OF ATIS A ON ZSSS"
	atis := transformer.Transform(rawAtis)
	generator := &EnglishAtisGenerator{}
	text := generator.Generate(atis)
	t.Log(text)
	tts := NewAliYunTTS("sk-981663c5aa984959adec9117d14f75a9")
	audio, err := tts.Synthesize(text)
	if err != nil {
		t.Error(err)
	}
	t.Log(len(audio))
	os.WriteFile("test.pcm", audio, 0644)
}
