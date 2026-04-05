// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package database
package database

import (
	"context"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type MetaOperation struct {
	logger  log.LoggerInterface
	db      *gorm.DB
	timeout time.Duration
}

func NewMetaOperation(logger log.LoggerInterface, db *gorm.DB, timeout time.Duration) *MetaOperation {
	return &MetaOperation{
		logger:  logger,
		db:      db,
		timeout: timeout,
	}
}

func (op *MetaOperation) GetMeta(key string) (meta *operation.Meta, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), op.timeout)
	defer cancel()
	meta = &operation.Meta{}
	if err = op.db.WithContext(ctx).Where("key = ?", key).First(meta).Error; err != nil {
		op.logger.ErrorF("Failed to get meta: %v", err)
		return nil, err
	}
	return meta, nil
}

func (op *MetaOperation) SetMeta(key, value string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), op.timeout)
	defer cancel()
	meta := &operation.Meta{
		Key:   key,
		Value: value,
	}
	if err = op.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(meta).Error; err != nil {
		op.logger.ErrorF("Failed to set meta: %v", err)
		return err
	}
	return nil
}
