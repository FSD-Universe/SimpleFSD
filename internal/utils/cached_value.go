// Package utils
package utils

import (
	"sync"
	"time"
)

type CachedValue[T any] struct {
	generateTime time.Time
	cachedData   T
	mu           sync.RWMutex
	cachedTime   time.Duration
	getter       func() T
	isSet        bool
}

func NewCachedValue[T any](cachedTime time.Duration, getter func() T) *CachedValue[T] {
	var zero T
	value := &CachedValue[T]{
		generateTime: time.Now(),
		cachedData:   zero,
		mu:           sync.RWMutex{},
		cachedTime:   cachedTime,
		getter:       getter,
		isSet:        false,
	}
	if cachedTime <= 0 {
		value.cachedData = getter()
		value.isSet = true
	}
	return value
}

func (cachedValue *CachedValue[T]) GetValue() T {
	if cachedValue.cachedTime <= 0 {
		return cachedValue.cachedData
	}
	cachedValue.mu.RLock()
	if cachedValue.isSet && time.Since(cachedValue.generateTime) <= cachedValue.cachedTime {
		defer cachedValue.mu.RUnlock()
		return cachedValue.cachedData
	}
	cachedValue.mu.RUnlock()

	cachedValue.mu.Lock()
	defer cachedValue.mu.Unlock()

	if cachedValue.isSet && time.Since(cachedValue.generateTime) <= cachedValue.cachedTime {
		return cachedValue.cachedData
	}

	cachedValue.cachedData = cachedValue.getter()
	cachedValue.generateTime = time.Now()
	cachedValue.isSet = true

	return cachedValue.cachedData
}
