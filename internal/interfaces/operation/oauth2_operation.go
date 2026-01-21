package operation

import (
	"time"

	"gorm.io/gorm"
)

// OAuth2Client OAuth2客户端应用
type OAuth2Client struct {
	ID           uint     `gorm:"primarykey"`
	ClientID     string   `gorm:"uniqueIndex;size:64;not null"`       // 客户端ID
	ClientSecret string   `gorm:"size:128;not null"`                  // 客户端密钥
	Name         string   `gorm:"size:128;not null"`                  // 应用名称
	RedirectURIs []string `gorm:"type:text;serializer:json;not null"` // 重定向URI
	Scopes       []string `gorm:"type:text;serializer:json;not null"` // 授权范围
	Enabled      bool     `gorm:"not null;default:true"`              // 是否启用
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt

	Codes  []*OAuth2AuthorizationCode `gorm:"foreignKey:ClientID;references:ClientID;constraint:OnUpdate:cascade,OnDelete:cascade"`
	Tokens []*OAuth2Token             `gorm:"foreignKey:ClientID;references:ClientID;constraint:OnUpdate:cascade,OnDelete:cascade"`
}

// OAuth2AuthorizationCode OAuth2授权码
type OAuth2AuthorizationCode struct {
	ID          uint      `gorm:"primarykey"`
	ClientID    string    `gorm:"index;size:64;not null"`       // 客户端ID
	UserID      uint      `gorm:"default:0"`                    // 用户ID
	Code        string    `gorm:"uniqueIndex;size:32;not null"` // 授权码
	ExpiresAt   time.Time `gorm:"not null"`                     // 过期时间
	Scopes      string    `gorm:"type:text;not null"`           // 授权范围
	State       string    `gorm:"size:128;not null"`            // CSRF验证
	Approved    *bool     `gorm:"default:null"`                 // 是否已批准
	RedirectURI string    `gorm:"type:text;not null"`           // 重定向URI
	Challenge   string    `gorm:"size:128;not null"`            // PKCE challenge
	CreatedAt   time.Time

	Client *OAuth2Client `gorm:"foreignKey:ClientID;references:ClientID;constraint:OnUpdate:cascade,OnDelete:cascade"`
}

// OAuth2Token OAuth2访问令牌
type OAuth2Token struct {
	ID           uint      `gorm:"primarykey"`
	ClientID     string    `gorm:"index;size:64;not null"` // 客户端ID
	UserID       uint      `gorm:"index;not null"`         // 用户ID
	TokenType    string    `gorm:"size:32;not null"`       // 令牌类型
	Scopes       string    `gorm:"type:text;not null"`     // 授权范围
	RefreshToken string    `gorm:"uniqueIndex"`            // 刷新令牌
	ExpiresAt    time.Time `gorm:"not null"`               // 过期时间
	CreatedAt    time.Time

	User   *User         `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:cascade,OnDelete:cascade"`
	Client *OAuth2Client `gorm:"foreignKey:ClientID;references:ClientID;constraint:OnUpdate:cascade,OnDelete:cascade"`
}

// OAuth2OperationInterface OAuth2操作接口
type OAuth2OperationInterface interface {
	CreateClient(client *OAuth2Client) error
	GetByID(id int) (*OAuth2Client, error)
	GetByClientID(clientID string) (*OAuth2Client, error)
	GetClientPage(pageNumber int, pageSize int) (clients []*OAuth2Client, total int64, err error)
	UpdateClient(clientID int, updates map[string]interface{}) error
	DeleteClient(clientID int) error

	CreateAuthorizationCode(code *OAuth2AuthorizationCode) error
	GetAuthorizationCode(code string) (*OAuth2AuthorizationCode, error)
	GetAuthorizationCodeById(id uint) (*OAuth2AuthorizationCode, error)
	UpdateAuthorizationCodeById(id uint, updates map[string]interface{}) error
	DeleteAuthorizationCode(code string) error

	CreateToken(token *OAuth2Token) error
	GetToken(token string) (*OAuth2Token, error)
	DeleteToken(clientId string, userId uint, token string) error
	UpdateTokenExpiresAt(token string, expiresAt time.Time) error

	CleanupExpiredTokens() error
}
