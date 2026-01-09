package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ActivityOperation struct {
	logger       log.LoggerInterface
	db           *gorm.DB
	queryTimeout time.Duration
}

func NewActivityOperation(
	logger log.LoggerInterface,
	db *gorm.DB,
	queryTimeout time.Duration,
) *ActivityOperation {
	return &ActivityOperation{
		logger:       logger,
		db:           db,
		queryTimeout: queryTimeout,
	}
}

func (activityOperation *ActivityOperation) NewActivity(user *User, title string, imageUrl string, activeTime time.Time, dep string, arr string, route string, distance int, notams string) (activity *Activity) {
	return &Activity{
		Publisher:        user.Cid,
		Title:            title,
		ImageUrl:         imageUrl,
		ActiveTime:       activeTime,
		DepartureAirport: dep,
		ArrivalAirport:   arr,
		Route:            route,
		Distance:         distance,
		Status:           int(Open),
		NOTAMS:           notams,
	}
}

func (activityOperation *ActivityOperation) NewActivityFacility(activity *Activity, rating int, callsign string, frequency float64) (activityFacility *ActivityFacility) {
	return &ActivityFacility{
		ActivityId: activity.ID,
		MinRating:  rating,
		Callsign:   callsign,
		Frequency:  fmt.Sprintf("%.3f", frequency),
	}
}

func (activityOperation *ActivityOperation) NewActivityAtc(facility *ActivityFacility, user *User) (activityAtc *ActivityATC) {
	return &ActivityATC{
		ActivityId: facility.ActivityId,
		FacilityId: facility.ID,
		UserId:     user.ID,
	}
}

func (activityOperation *ActivityOperation) NewActivityPilot(activityId uint, id uint, callsign string, aircraftType string) (activityPilot *ActivityPilot) {
	return &ActivityPilot{
		ActivityId:   activityId,
		UserId:       id,
		Callsign:     callsign,
		AircraftType: aircraftType,
		Status:       int(Signed),
	}
}

func (activityOperation *ActivityOperation) GetActivities(startDay, endDay time.Time) (activities []*Activity, err error) {
	activities = make([]*Activity, 0)
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	err = activityOperation.db.WithContext(ctx).Where("active_time between ? and ?", startDay, endDay).Find(&activities).Error
	return
}

func (activityOperation *ActivityOperation) GetActivitiesPage(page, pageSize int) (activities []*Activity, total int64, err error) {
	activities = make([]*Activity, 0, pageSize)
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	activityOperation.db.WithContext(ctx).Model(&Activity{}).Select("id").Count(&total)
	err = activityOperation.db.WithContext(ctx).Offset((page - 1) * pageSize).Limit(pageSize).Find(&activities).Error
	return
}

func (activityOperation *ActivityOperation) GetActivityById(activityId uint) (activity *Activity, err error) {
	activity = &Activity{}
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	err = activityOperation.db.WithContext(ctx).
		Preload("Pilots", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at")
		}).
		Preload("Pilots.User", func(db *gorm.DB) *gorm.DB {
			return db.Select("id, cid, avatar_url")
		}).
		Preload("Facilities.Controller").
		Preload("Facilities.Controller.User", func(db *gorm.DB) *gorm.DB {
			return db.Select("id, cid, avatar_url")
		}).
		Preload("Controllers").
		Where("id = ?", activityId).
		First(activity).
		Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = ErrActivityNotFound
	}
	return
}

func (activityOperation *ActivityOperation) SaveActivity(activity *Activity) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.Clauses(clause.Locking{Strength: "UPDATE"}).WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if activity.ID == 0 {
			return tx.WithContext(ctx).Create(activity).Error
		}
		return tx.WithContext(ctx).Save(activity).Error
	})
}

func (activityOperation *ActivityOperation) DeleteActivity(activityId uint) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.Clauses(clause.Locking{Strength: "UPDATE"}).WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.WithContext(ctx).Delete(&Activity{}, activityId)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrActivityNotFound
		}
		return nil
	})
}

func (activityOperation *ActivityOperation) SetActivityStatus(activityId uint, status ActivityStatus) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.WithContext(ctx).Model(&Activity{ID: activityId}).Update("status", int(status)).Error
}

func (activityOperation *ActivityOperation) SetActivityPilotStatus(activityPilot *ActivityPilot, status ActivityPilotStatus) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.WithContext(ctx).Model(activityPilot).Update("status", int(status)).Error
}

func (activityOperation *ActivityOperation) GetFacilityById(facilityId uint) (facility *ActivityFacility, err error) {
	facility = &ActivityFacility{}
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	err = activityOperation.db.WithContext(ctx).Preload("Controller").First(facility, facilityId).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = ErrFacilityNotFound
	}
	return
}

func (activityOperation *ActivityOperation) GetActivityPilotById(activityId uint, userId uint) (pilot *ActivityPilot, err error) {
	pilot = &ActivityPilot{}
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	err = activityOperation.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Where("activity_id = ? and user_id = ?", activityId, userId).First(pilot).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrActivityUnsigned
		}
		return err
	})
	return
}

func (activityOperation *ActivityOperation) SignFacilityController(facility *ActivityFacility, user *User) (err error) {
	if user.Rating < facility.MinRating || (facility.Tier2Tower && !user.Tier2) {
		return ErrRatingNotAllowed
	}
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		controller := &ActivityATC{}
		tx.Select("id").Where("activity_id = ? and user_id = ?", facility.ActivityId, user.ID).First(controller)
		if controller.ID != 0 {
			return ErrFacilityAlreadyExists
		}
		activityController := activityOperation.NewActivityAtc(facility, user)
		err := tx.Create(activityController).Error
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrFacilitySigned
		}
		return err
	})
}

func (activityOperation *ActivityOperation) UnsignFacilityController(facility *ActivityFacility, userId uint) (err error) {
	if facility.Controller == nil {
		return ErrFacilityNotSigned
	}
	if facility.Controller.UserId != userId {
		return ErrFacilityNotYourSign
	}
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.Clauses(clause.Locking{Strength: "UPDATE"}).WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		controller := &ActivityATC{}
		tx.Select("id").Where("activity_id = ? and facility_id = ? and user_id = ?", facility.ActivityId, facility.ID, userId).First(controller)
		if controller.ID == 0 {
			return ErrFacilityNotSigned
		}
		return tx.Delete(controller).Error
	})
}

func (activityOperation *ActivityOperation) SignActivityPilot(activityId uint, userId uint, callsign string, aircraftType string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		pilot := &ActivityPilot{}
		tx.Select("id", "user_id", "callsign").Where("activity_id = ? and (user_id = ? or callsign = ?)", activityId, userId, callsign).First(pilot)
		if pilot.ID != 0 {
			if pilot.UserId == userId {
				return ErrActivityAlreadySigned
			}
			return ErrCallsignAlreadyUsed
		}
		activityPilot := activityOperation.NewActivityPilot(activityId, userId, callsign, aircraftType)
		err := tx.Create(activityPilot).Error
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrActivityAlreadySigned
		}
		return err
	})
}

func (activityOperation *ActivityOperation) UnsignActivityPilot(activityId uint, userId uint) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.Clauses(clause.Locking{Strength: "UPDATE"}).WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		pilot := &ActivityPilot{}
		tx.Select("id").Where("activity_id = ? and user_id = ?", activityId, userId).First(pilot)
		if pilot.ID == 0 {
			return ErrActivityUnsigned
		}
		return tx.Delete(pilot).Error
	})
}

func (activityOperation *ActivityOperation) UpdateActivityInfo(oldActivity *Activity, newActivity *Activity, updateInfo map[string]interface{}) (err error) {
	oldFacilities := oldActivity.Facilities
	newFacilities := newActivity.Facilities

	deleteFacilities := make([]*ActivityFacility, 0)
	insertFacilities := make([]*ActivityFacility, 0)
	updateFacilities := make(map[uint]map[string]interface{})

	// 创建旧席位的映射，便于快速查找
	oldFacilityMap := make(map[uint]*ActivityFacility)
	for _, facility := range oldFacilities {
		oldFacilityMap[facility.ID] = facility
	}

	// 处理新席位
	for _, newFacility := range newFacilities {
		if newFacility.ID == 0 {
			// 新增席位
			newFacility.ActivityId = newActivity.ID
			insertFacilities = append(insertFacilities, newFacility)
		} else if oldFacility, exists := oldFacilityMap[newFacility.ID]; exists {
			// 检查是否需要更新
			if !newFacility.Equal(oldFacility) {
				updateFacilities[newFacility.ID] = newFacility.Diff(oldFacility)
			}
			// 从映射中移除
			delete(oldFacilityMap, newFacility.ID)
		} else {
			// 注意：如果newFacility.ID不为0但在oldFacilityMap中不存在
			// 这可能表示数据不一致，可能是脏读导致的数据错误，也可能是有人恶意注入，直接报错退出就行
			return ErrInconsistentData
		}
	}

	// 剩余在oldFacilityMap中的席位是需要删除的
	for _, facility := range oldFacilityMap {
		deleteFacilities = append(deleteFacilities, facility)
	}

	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	return activityOperation.db.Clauses(clause.Locking{Strength: "UPDATE"}).WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 更新活动基础信息
		if err := tx.Model(oldActivity).Updates(updateInfo).Error; err != nil {
			return err
		}

		// 外键已配置级联删除, 这里直接批量删除即可
		if len(deleteFacilities) > 0 {
			if err := tx.Delete(deleteFacilities).Error; err != nil {
				return err
			}
		}

		if len(insertFacilities) > 0 {
			if err := tx.Create(insertFacilities).Error; err != nil {
				return err
			}
		}

		if len(updateFacilities) > 0 {
			for id, updateData := range updateFacilities {
				if err := tx.Model(&ActivityFacility{ID: id}).Updates(updateData).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (activityOperation *ActivityOperation) GetTotalActivities() (total int64, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), activityOperation.queryTimeout)
	defer cancel()
	err = activityOperation.db.WithContext(ctx).Model(&Activity{}).Select("id").Count(&total).Error
	return
}
