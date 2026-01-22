// Package controller
package controller

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/labstack/echo/v4"
)

type JwtInfoSetter interface {
	SetUid(uid uint)
	SetCid(cid int)
	SetPermission(permission uint64)
	SetRating(rating int)
	SetTokenType(tokenType service.TokenType)
	SetScopes(scopes string)
}

func SetJwtInfo[T JwtInfoSetter](data T, ctx echo.Context) error {
	token, ok := ctx.Get("user").(*jwt.Token)
	if !ok {
		return errors.New("JWT token not found in context")
	}
	claim, ok := token.Claims.(*service.Claims)
	if !ok {
		return errors.New("invalid claim type")
	}
	data.SetPermission(claim.Permission)
	data.SetUid(claim.Uid)
	data.SetCid(claim.Cid)
	data.SetRating(claim.Rating)
	data.SetTokenType(service.TokenType(claim.TokenType))
	data.SetScopes(claim.Scopes)
	return nil
}

type EchoContentSetter interface {
	SetIp(ip string)
	SetUserAgent(ua string)
}

func SetEchoContent[T EchoContentSetter](data T, ctx echo.Context) {
	data.SetIp(ctx.RealIP())
	data.SetUserAgent(ctx.Request().UserAgent())
}

func SetJwtInfoAndEchoContent[T interface {
	JwtInfoSetter
	EchoContentSetter
}](data T, ctx echo.Context) error {
	if err := SetJwtInfo(data, ctx); err != nil {
		return err
	}
	SetEchoContent(data, ctx)
	return nil
}
