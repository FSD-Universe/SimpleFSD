// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package utils
package utils

func ClearMap[K comparable, V any](m map[K]V) {
	for k := range m {
		delete(m, k)
	}
}

func MergeMap[K comparable, V any](dst, src map[K]V) {
	for k, v := range src {
		dst[k] = v
	}
}
