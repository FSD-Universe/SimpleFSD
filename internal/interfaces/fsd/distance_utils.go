package fsd

import (
	"math"
)

const (
	earthRadiusMeters     = 6371000
	metersPerNauticalMile = 1852
)

// DistanceInNauticalMiles 使用球面余弦定理计算两点间距离
func DistanceInNauticalMiles(p1, p2 Position) float64 {
	lat1 := p1.Latitude * math.Pi / 180
	lon1 := p1.Longitude * math.Pi / 180
	lat2 := p2.Latitude * math.Pi / 180
	lon2 := p2.Longitude * math.Pi / 180

	centralAngle := math.Acos(math.Sin(lat1)*math.Sin(lat2) + math.Cos(lat1)*math.Cos(lat2)*math.Cos(lon2-lon1))

	return (earthRadiusMeters * centralAngle) / metersPerNauticalMile
}

// FindNearestDistance 查找两组点之间的最近距离
func FindNearestDistance(groupA, groupB [4]Position) (minDistance float64) {
	minDistance = math.MaxFloat64
	for _, a := range groupA {
		if !a.PositionValid() {
			continue
		}
		for _, b := range groupB {
			if !b.PositionValid() {
				continue
			}
			distance := DistanceInNauticalMiles(a, b)
			if distance <= 0 {
				return 0
			}
			if distance < minDistance {
				minDistance = distance
			}
		}
	}
	return
}
