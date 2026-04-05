// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package operation
package operation

import "time"

type Meta struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	Key       string    `gorm:"size:128;uniqueIndex;not null" json:"key"`
	Value     string    `gorm:"size:128;not null" json:"value"`
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
}

type MetaOperationInterface interface {
	GetMeta(key string) (meta *Meta, err error)
	SetMeta(key, value string) (err error)
}
