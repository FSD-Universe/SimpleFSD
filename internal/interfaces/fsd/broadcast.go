// Package fsd
package fsd

import (
	"math"
)

type BroadcastTarget string

var (
	AllClient BroadcastTarget = "*"
	AllPilot  BroadcastTarget = "*P"
	AllATC    BroadcastTarget = "*A"
	AllSup    BroadcastTarget = "*S"
)

func IsValidBroadcastTarget(b string) bool {
	target := BroadcastTarget(b)
	return target == AllSup || target == AllATC || target == AllClient || target == AllPilot
}

func (b BroadcastTarget) String() string {
	return string(b)
}

func (b BroadcastTarget) Index() int {
	return 0
}

type ClientFilter func(client ClientInterface) bool

type BroadcastFilter func(toClient, fromClient ClientInterface) bool

func BroadcastToAllPilotClient(client ClientInterface) bool {
	return !client.IsAtc()
}

func BroadcastToAllClient(_ ClientInterface) bool {
	return true
}

func BroadcastToATCClient(client ClientInterface) bool {
	return client.IsAtc()
}

func BroadcastToSupClient(client ClientInterface) bool {
	if !client.IsAtc() {
		return false
	}
	return client.Rating() >= Supervisor
}

func BroadcastToAll(_, _ ClientInterface) bool {
	return true
}

func BroadcastToPilot(toClient, _ ClientInterface) bool {
	return !toClient.IsAtc()
}

func BroadcastToAtc(toClient, _ ClientInterface) bool {
	return toClient.IsAtc()
}

func BroadcastToSup(toClient, _ ClientInterface) bool {
	if !toClient.IsAtc() {
		return false
	}
	return toClient.Rating() >= Supervisor
}

func BroadcastToClientInRange(toClient, fromClient ClientInterface) bool {
	if fromClient == nil {
		return true
	}
	var threshold float64 = 0
	switch {
	case toClient.IsAtc() && fromClient.IsAtc():
		threshold = math.Max(toClient.VisualRange(), fromClient.VisualRange())
	case toClient.IsAtc():
		threshold = toClient.VisualRange()
	case fromClient.IsAtc():
		threshold = fromClient.VisualRange()
	default:
		threshold = toClient.VisualRange() + fromClient.VisualRange()
	}
	distance := FindNearestDistance(toClient.Position(), fromClient.Position())
	return distance <= threshold
}

func BroadcastToClientInRangeWithVoiceRange(toClient, fromClient ClientInterface) bool {
	if fromClient == nil {
		return true
	}
	threshold := fromClient.VoiceRange() + toClient.VoiceRange()
	distance := FindNearestDistance(toClient.Position(), fromClient.Position())
	return distance <= threshold
}

func CombineBroadcastFilter(filters ...BroadcastFilter) BroadcastFilter {
	return func(toClient, fromClient ClientInterface) bool {
		for _, f := range filters {
			if f == nil {
				continue
			}
			if !f(toClient, fromClient) {
				return false
			}
		}
		return true
	}
}
