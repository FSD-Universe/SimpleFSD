// Package operation
package operation

import (
	"errors"
	"time"

	"github.com/half-nothing/simple-fsd/internal/utils"
	"gorm.io/gorm"
)

type User struct {
	ID                uint                `gorm:"primarykey" json:"id"`
	Username          string              `gorm:"size:64;uniqueIndex;not null" json:"username"`
	Email             string              `gorm:"size:128;uniqueIndex;not null" json:"email"`
	Cid               int                 `gorm:"uniqueIndex;not null" json:"cid"`
	Password          string              `gorm:"size:128;not null" json:"-"`
	AvatarUrl         string              `gorm:"size:128;not null;default:''" json:"avatar_url"`
	QQ                int                 `gorm:"default:0" json:"qq"`
	Rating            int                 `gorm:"default:0" json:"rating"`
	Guest             bool                `gorm:"default:false" json:"guest"`
	UnderMonitor      bool                `gorm:"default:false;not null" json:"under_monitor"`
	UnderSolo         bool                `gorm:"default:false;not null" json:"under_solo"`
	Tier2             bool                `gorm:"default:false;not null" json:"tier2"`
	SoloUntil         *time.Time          `gorm:"default:null" json:"solo_until"`
	Permission        uint64              `gorm:"default:0" json:"permission"`
	TotalPilotTime    int                 `gorm:"default:0" json:"total_pilot_time"`
	TotalAtcTime      int                 `gorm:"default:0" json:"total_atc_time"`
	FlightPlans       []*FlightPlan       `gorm:"foreignKey:Cid;references:Cid;constraint:OnUpdate:cascade,OnDelete:cascade;" json:"-"`
	OnlineHistories   []*History          `gorm:"foreignKey:Cid;references:Cid;constraint:OnUpdate:cascade,OnDelete:cascade;" json:"-"`
	ActivityAtc       []*ActivityATC      `gorm:"foreignKey:UserId;references:ID;constraint:OnUpdate:cascade,OnDelete:cascade;" json:"-"`
	ActivityPilot     []*ActivityPilot    `gorm:"foreignKey:UserId;references:ID;constraint:OnUpdate:cascade,OnDelete:cascade;" json:"-"`
	AuditLogs         []*AuditLog         `gorm:"foreignKey:Subject;references:Cid;constraint:OnUpdate:cascade,OnDelete:cascade;" json:"-"`
	ControllerRecords []*ControllerRecord `gorm:"foreignKey:UserId;references:ID;constraint:OnUpdate:cascade,OnDelete:cascade;" json:"-"`
	Tickets           []*Ticket           `gorm:"foreignKey:UserId;references:ID;constraint:OnUpdate:cascade,OnDelete:cascade;" json:"-"`
	CreatedAt         *time.Time          `json:"register_time"`
	UpdatedAt         time.Time           `json:"-"`
}

var (
	// ErrUserNotFound 用户不存在
	ErrUserNotFound = errors.New("user does not exist")
	// ErrIdentifierTaken 三元组一致性检查失败
	ErrIdentifierTaken = errors.New("user identifiers have been used")
	// ErrIdentifierCheck 三元组一致性检查异常
	ErrIdentifierCheck = errors.New("identifier check error")
	// ErrPasswordEncode 密码编码错误
	ErrPasswordEncode = errors.New("password encode error")
	// ErrOldPassword 原密码错误
	ErrOldPassword = errors.New("old password error")
)

type UserId interface {
	GetUser(userOperation UserOperationInterface) (*User, error)
}

func GetUserId(userId string) UserId {
	id := utils.StrToInt(userId, -1)
	if id == -1 {
		return StringUserId(userId)
	}
	return IntUserId(id)
}

type IntUserId int
type StringUserId string

func (id IntUserId) GetUser(userOperation UserOperationInterface) (*User, error) {
	return userOperation.GetUserByCid(int(id))
}

func (id StringUserId) GetUser(userOperation UserOperationInterface) (*User, error) {
	return userOperation.GetUserByUsernameOrEmail(string(id))
}

// UserOperationInterface 用户操作接口定义
type UserOperationInterface interface {
	// GetUserByUid 通过主键ID获取用户, 当err为nil时返回值user有效
	GetUserByUid(uid uint) (user *User, err error)
	// GetUserByCid 通过Cid获取用户, 当err为nil时返回值user有效
	GetUserByCid(cid int) (user *User, err error)
	// GetUserByUsername 通过用户名获取用户, 当err为nil时返回值user有效
	GetUserByUsername(username string) (user *User, err error)
	// GetUserByEmail 通过邮箱获取用户, 当err为nil时返回值user有效
	GetUserByEmail(email string) (user *User, err error)
	// GetUserByUsernameOrEmail 通过用户名或者邮箱获取用户, 当err为nil时返回值user有效
	GetUserByUsernameOrEmail(ident string) (user *User, err error)
	// GetUsers 获取分页用户数据, 当err为nil时返回值users有效, total表示数据总数目
	GetUsers(page, pageSize int) (users []*User, total int64, err error)
	// NewUser 创建一个新用户(只是创建, 没有写入数据库), 当err为nil时返回值user有效
	NewUser(username string, email string, cid int, password string) (user *User, err error)
	// AddUser 创建一个新用户(写入数据库), 在写入之前会调用 [UserOperationInterface.IsUserIdentifierTaken] 检查一致性约束, 当err为nil时表示创建成功
	AddUser(user *User) (err error)
	// UpdateUserAtcTime 更新用户管制时间, 当err为nil时表示更新成功
	UpdateUserAtcTime(user *User, seconds int) (err error)
	// UpdateUserPilotTime 更新用户连线飞行时间, 当err为nil时表示更新成功
	UpdateUserPilotTime(user *User, seconds int) (err error)
	// UpdateUserPermission 更新用户飞控权限, 当err为nil时表示更新成功
	UpdateUserPermission(user *User, permission Permission) (err error)
	// UpdateUserInfo 批量更新用户信息, 当err为nil时表示更新成功
	UpdateUserInfo(user *User, info *User) (err error)
	// UpdateUserPassword 更新用户密码(不写入数据库, 仅验证), 当err为nil时返回值encodePassword有效
	UpdateUserPassword(user *User, originalPassword, newPassword string, skipVerify bool) (encodePassword []byte, err error)
	// SaveUser 保存用户数据, 强制整个用户结构体到数据库, 谨慎使用, 当err为nil时表示更新成功
	SaveUser(user *User) (err error)
	// VerifyUserPassword 验证用户密码是否正确, pass为true表示验证通过
	VerifyUserPassword(user *User, password string) (pass bool)
	// IsUserIdentifierTaken 检查给定用户三元组的一致性约束, err为nil且taken为true时表示一致性约束检查通过
	IsUserIdentifierTaken(tx *gorm.DB, cid int, username, email string) (taken bool, err error)
	GetTotalUsers() (total int64, err error)
	GetTimeRatings() (pilots []*User, controllers []*User, err error)
}
