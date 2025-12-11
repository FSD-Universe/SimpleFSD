package fsd

type Enum interface {
	String() string
	Index() int
}

const (
	ClientQueryBroadcastFrequency       = "@94835"
	ClientQueryBroadcastFrequencyClient = "@94836"
)

const AllowAtcFacility = DEL | GND | TWR | APP | CTR | FSS

var AllowKillRating = []Rating{Supervisor, Administrator}

var RatingFacilityMap = map[Rating]Facility{
	Ban:           0,
	Normal:        Pilot,
	Observer:      Pilot | OBS,
	STU1:          Pilot | OBS | DEL | GND | RMP,
	STU2:          Pilot | OBS | DEL | GND | RMP | TWR,
	STU3:          Pilot | OBS | DEL | GND | RMP | TWR | APP,
	CTR1:          Pilot | OBS | DEL | GND | RMP | TWR | APP | CTR,
	CTR2:          Pilot | OBS | DEL | GND | RMP | TWR | APP | CTR,
	CTR3:          Pilot | OBS | DEL | GND | RMP | TWR | APP | CTR | FSS,
	Instructor1:   Pilot | OBS | DEL | GND | RMP | TWR | APP | CTR | FSS,
	Instructor2:   Pilot | OBS | DEL | GND | RMP | TWR | APP | CTR | FSS,
	Instructor3:   Pilot | OBS | DEL | GND | RMP | TWR | APP | CTR | FSS,
	Supervisor:    Pilot | OBS | DEL | GND | RMP | TWR | APP | CTR | FSS | SUP,
	Administrator: Pilot | OBS | DEL | GND | RMP | TWR | APP | CTR | FSS | SUP | ADM,
}

var FacilityMap = map[string]Facility{
	"ADM":  ADM,
	"SUP":  SUP,
	"OBS":  OBS,
	"DEL":  DEL,
	"RMP":  RMP,
	"GND":  GND,
	"TWR":  TWR,
	"APP":  APP,
	"CTR":  CTR,
	"FSS":  FSS,
	"ATIS": TWR,
}
