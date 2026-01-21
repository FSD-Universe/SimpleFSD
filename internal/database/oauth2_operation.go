package database

import (
	"context"
	"time"

	. "github.com/half-nothing/simple-fsd/internal/interfaces/log"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"gorm.io/gorm"
)

// OAuth2Operation OAuth2操作接口
type OAuth2Operation struct {
	logger  LoggerInterface
	db      *gorm.DB
	timeout time.Duration
}

// NewOAuth2Operation 创建OAuth2操作实例
func NewOAuth2Operation(logger LoggerInterface, db *gorm.DB, timeout time.Duration) *OAuth2Operation {
	return &OAuth2Operation{
		logger:  logger,
		db:      db,
		timeout: timeout,
	}
}

// CreateClient 创建OAuth2客户端
func (o *OAuth2Operation) CreateClient(client *OAuth2Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	if err := o.db.WithContext(ctx).Create(client).Error; err != nil {
		o.logger.ErrorF("Failed to create OAuth2 client: %v", err)
		return err
	}
	return nil
}

func (o *OAuth2Operation) GetByID(id int) (*OAuth2Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	client := &OAuth2Client{}
	if err := o.db.WithContext(ctx).Where("id = ? AND enabled = ?", id, true).First(client).Error; err != nil {
		o.logger.ErrorF("Failed to get OAuth2 client: %v", err)
		return nil, err
	}
	return client, nil
}

func (o *OAuth2Operation) GetByClientID(clientID string) (*OAuth2Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	client := &OAuth2Client{}
	if err := o.db.WithContext(ctx).Where("client_id = ? AND enabled = ?", clientID, true).First(client).Error; err != nil {
		o.logger.ErrorF("Failed to get OAuth2 client: %v", err)
		return nil, err
	}
	return client, nil
}

func (o *OAuth2Operation) GetClientPage(pageNumber int, pageSize int) (clients []*OAuth2Client, total int64, err error) {
	clients = make([]*OAuth2Client, 0, pageSize)

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	o.db.WithContext(ctx).Model(&OAuth2Client{}).Select("id").Count(&total)
	err = o.db.WithContext(ctx).Offset((pageNumber - 1) * pageSize).Order("cid").Limit(pageSize).Find(&clients).Error
	return
}

func (o *OAuth2Operation) UpdateClient(clientID int, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	if err := o.db.WithContext(ctx).Model(&OAuth2Client{}).Where("id = ?", clientID).Updates(updates).Error; err != nil {
		o.logger.ErrorF("Failed to update OAuth2 client: %v", err)
		return err
	}
	return nil
}

func (o *OAuth2Operation) DeleteClient(clientID int) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	if err := o.db.WithContext(ctx).Where("id = ?", clientID).Delete(&OAuth2Client{}).Error; err != nil {
		o.logger.ErrorF("Failed to delete OAuth2 client: %v", err)
		return err
	}
	return nil
}

func (o *OAuth2Operation) CreateAuthorizationCode(code *OAuth2AuthorizationCode) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	if err := o.db.WithContext(ctx).Create(code).Error; err != nil {
		o.logger.ErrorF("Failed to create authorization code: %v", err)
		return err
	}
	return nil
}

func (o *OAuth2Operation) GetAuthorizationCode(code string) (*OAuth2AuthorizationCode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	authCode := &OAuth2AuthorizationCode{}
	if err := o.db.WithContext(ctx).Where("code = ?", code).First(authCode).Error; err != nil {
		o.logger.ErrorF("Failed to get authorization code: %v", err)
		return nil, err
	}

	if authCode.ExpiresAt.Before(time.Now()) {
		_ = o.DeleteAuthorizationCode(code)
		return nil, gorm.ErrRecordNotFound
	}

	return authCode, nil
}

func (o *OAuth2Operation) GetAuthorizationCodeById(id uint) (*OAuth2AuthorizationCode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	authCode := &OAuth2AuthorizationCode{}
	if err := o.db.WithContext(ctx).Where("id = ?", id).First(authCode).Error; err != nil {
		o.logger.ErrorF("Failed to get authorization code: %v", err)
		return nil, err
	}
	return authCode, nil
}

func (o *OAuth2Operation) UpdateAuthorizationCodeById(id uint, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	if err := o.db.WithContext(ctx).
		Model(&OAuth2AuthorizationCode{}).
		Where("id = ?", id).
		Updates(updates).Error; err != nil {
		o.logger.ErrorF("Failed to update authorization code: %v", err)
		return err
	}
	return nil
}

func (o *OAuth2Operation) DeleteAuthorizationCode(code string) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	if err := o.db.WithContext(ctx).Where("code = ?", code).Delete(&OAuth2AuthorizationCode{}).Error; err != nil {
		o.logger.ErrorF("Failed to delete authorization code: %v", err)
		return err
	}
	return nil
}

func (o *OAuth2Operation) CreateToken(token *OAuth2Token) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	if err := o.db.WithContext(ctx).Create(token).Error; err != nil {
		o.logger.ErrorF("Failed to create access token: %v", err)
		return err
	}
	return nil
}

func (o *OAuth2Operation) GetToken(token string) (*OAuth2Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	accessToken := &OAuth2Token{}
	if err := o.db.WithContext(ctx).
		Where("refresh_token = ?", token).
		Joins("Client").
		First(&accessToken).Error; err != nil {
		o.logger.ErrorF("Failed to get token: %v", err)
		return nil, err
	}

	// 检查是否过期
	if accessToken.ExpiresAt.Before(time.Now()) {
		_ = o.DeleteToken(accessToken.ClientID, accessToken.UserID, accessToken.RefreshToken)
		return nil, gorm.ErrRecordNotFound
	}

	return accessToken, nil
}

func (o *OAuth2Operation) DeleteToken(clientId string, userId uint, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	query := o.db.WithContext(ctx).
		Where("client_id = ? AND user_id = ? AND refresh_token = ?", clientId, userId, token).
		Delete(&OAuth2Token{})
	if err := query.Error; err != nil {
		o.logger.ErrorF("Failed to delete token: %v", err)
		return err
	}
	if query.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (o *OAuth2Operation) UpdateTokenExpiresAt(token string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	if err := o.db.WithContext(ctx).
		Model(&OAuth2Token{}).
		Where("refresh_token = ?", token).
		Update("expires_at", expiresAt).Error; err != nil {
		o.logger.ErrorF("Failed to update token expires_at: %v", err)
		return err
	}
	return nil
}

func (o *OAuth2Operation) CleanupExpiredTokens() error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	// 清理过期的授权码
	if err := o.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&OAuth2AuthorizationCode{}).Error; err != nil {
		o.logger.ErrorF("Failed to cleanup expired authorization codes: %v", err)
		return err
	}

	// 清理过期的访问令牌
	if err := o.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&OAuth2Token{}).Error; err != nil {
		o.logger.ErrorF("Failed to cleanup expired access tokens: %v", err)
		return err
	}

	return nil
}
