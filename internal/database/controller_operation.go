// Package database
package database

import (
	"context"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/fsd"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ControllerOperation struct {
	logger       log.LoggerInterface
	db           *gorm.DB
	queryTimeout time.Duration
}

func NewControllerOperation(logger log.LoggerInterface, db *gorm.DB, queryTimeout time.Duration) *ControllerOperation {
	return &ControllerOperation{
		logger:       logger,
		db:           db,
		queryTimeout: queryTimeout,
	}
}

func (controllerOperation *ControllerOperation) GetTotalControllers() (total int64, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), controllerOperation.queryTimeout)
	defer cancel()
	err = controllerOperation.db.WithContext(ctx).Model(&User{}).Select("id").Where("rating > ?", fsd.Normal).Count(&total).Error
	return
}

func (controllerOperation *ControllerOperation) GetControllers(page, pageSize int, search string) (users []*User, total int64, err error) {
	users = make([]*User, 0, pageSize)
	ctx, cancel := context.WithTimeout(context.Background(), controllerOperation.queryTimeout)
	defer cancel()
	var totalSearch = controllerOperation.db.WithContext(ctx).Model(&User{}).Select("id").Where("rating > ?", fsd.Normal)
	var dataSearch = controllerOperation.db.WithContext(ctx).Offset((page-1)*pageSize).Order("cid").Where("rating > ?", fsd.Normal).Limit(pageSize)
	if search != "" {
		var likeSearch = "%" + search + "%"
		var intSearch = utils.StrToInt(search, -1)
		totalSearch.Where("username LIKE ? OR email LIKE ? OR cid = ?", likeSearch, likeSearch, intSearch)
		dataSearch.Where("username LIKE ? OR email LIKE ? OR cid = ?", likeSearch, likeSearch, intSearch)
	}
	totalSearch.Count(&total)
	err = dataSearch.Find(&users).Error
	return
}

func (controllerOperation *ControllerOperation) SetControllerRating(user *User, updateInfo map[string]interface{}) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), controllerOperation.queryTimeout)
	defer cancel()
	return controllerOperation.db.Clauses(clause.Locking{Strength: "UPDATE"}).WithContext(ctx).Model(user).Updates(updateInfo).Error
}
