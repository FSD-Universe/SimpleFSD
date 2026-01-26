package controller

import (
	"net/url"
	"strconv"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/labstack/echo/v4"
)

type OAuth2Controller struct {
	logger        log.LoggerInterface
	config        *config.OAuth2Config
	oauth2Service OAuth2ServiceInterface
}

func NewOAuth2Controller(
	lg log.LoggerInterface,
	config *config.OAuth2Config,
	oauth2Service OAuth2ServiceInterface,
) *OAuth2Controller {
	return &OAuth2Controller{
		logger:        log.NewLoggerAdapter(lg, "OAuth2Controller"),
		config:        config,
		oauth2Service: oauth2Service,
	}
}

func (c *OAuth2Controller) CreateClient(ctx echo.Context) error {
	req := &CreateClientRequest{}
	if err := ctx.Bind(req); err != nil {
		c.logger.ErrorF("CreateClient bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	if len(req.RedirectURIs) == 0 {
		return NewErrorResponse(ctx, NewApiStatus("MISSING_REDIRECT_URI", "重定向URI不能为空", BadRequest))
	}

	if len(req.Scopes) == 0 {
		return NewErrorResponse(ctx, NewApiStatus("MISSING_SCOPES", "授权范围不能为空", BadRequest))
	}

	SetEchoContent(req, ctx)
	if err := SetJwtInfo(req, ctx); err != nil {
		c.logger.ErrorF("CreateClient jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	return c.oauth2Service.CreateClient(req).Response(ctx)
}

func (c *OAuth2Controller) GetClientPage(ctx echo.Context) error {
	req := &GetClientsPageRequest{}
	if err := ctx.Bind(req); err != nil {
		c.logger.ErrorF("GetClientPage bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	if req.Page <= 0 || req.PageSize <= 0 {
		c.logger.ErrorF("GetClientPage page or pageSize error")
		return NewErrorResponse(ctx, ErrInvalidPageParam)
	}

	if err := SetJwtInfo(req, ctx); err != nil {
		c.logger.ErrorF("GetClientPage jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	return c.oauth2Service.GetClients(req).Response(ctx)
}

func (c *OAuth2Controller) UpdateClient(ctx echo.Context) error {
	req := &UpdateClientRequest{}
	if err := ctx.Bind(req); err != nil {
		c.logger.ErrorF("UpdateClient bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	if req.ClientID <= 0 {
		c.logger.ErrorF("UpdateClient clientID error")
		return NewErrorResponse(ctx, ErrIllegalParam)
	}

	if err := SetJwtInfo(req, ctx); err != nil {
		c.logger.ErrorF("UpdateClient jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	SetEchoContent(req, ctx)

	return c.oauth2Service.UpdateClient(req).Response(ctx)
}

func (c *OAuth2Controller) DeleteClient(ctx echo.Context) error {
	req := &DeleteClientRequest{}
	if err := ctx.Bind(req); err != nil {
		c.logger.ErrorF("DeleteClient bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	if req.ClientID <= 0 {
		c.logger.ErrorF("DeleteClient clientID error")
		return NewErrorResponse(ctx, ErrIllegalParam)
	}

	if err := SetJwtInfo(req, ctx); err != nil {
		c.logger.ErrorF("DeleteClient jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	SetEchoContent(req, ctx)

	return c.oauth2Service.DeleteClient(req).Response(ctx)
}

func (c *OAuth2Controller) Authorize(ctx echo.Context) error {
	req := &AuthorizeRequest{}
	if err := ctx.Bind(req); err != nil {
		c.logger.ErrorF("Authorize bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	if req.ClientID == "" {
		c.logger.ErrorF("Authorize clientID error")
		return NewJsonResponse(ctx, BadRequest, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidRequest.ErrorCode,
			ErrorDescription: "Missing client_id",
		})
	}

	if req.RedirectURI == "" {
		c.logger.ErrorF("Authorize redirectURI error")
		return NewJsonResponse(ctx, BadRequest, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidRequest.ErrorCode,
			ErrorDescription: "Missing redirect_uri",
		})
	}

	if req.ResponseType == "" {
		c.logger.ErrorF("Authorize responseType error")
		return NewJsonResponse(ctx, BadRequest, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidRequest.ErrorCode,
			ErrorDescription: "Missing response_type",
		})
	}

	if c.config.RequirePKCE && req.CodeChallenge == "" {
		c.logger.ErrorF("Authorize codeChallenge error")
		return NewJsonResponse(ctx, BadRequest, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidRequest.ErrorCode,
			ErrorDescription: "Missing code_challenge",
		})
	}

	res, code := c.oauth2Service.Authorize(req)
	if res == nil {
		authorizationPage, _ := url.Parse(c.config.AuthorizationPageURL)
		query := url.Values{}
		query.Set("id", strconv.Itoa(int(code.ID)))
		query.Set("app_name", code.Client.Name)
		query.Set("scopes", code.Scopes)
		authorizationPage.RawQuery = query.Encode()

		c.logger.InfoF("Authorize redirect to %s", authorizationPage.String())

		return ctx.Redirect(Found.Code(), authorizationPage.String())
	}

	return NewJsonResponse(ctx, BadRequest, res)
}

func (c *OAuth2Controller) authorization(ctx echo.Context) (*AuthorizationRequest, error) {
	req := &AuthorizationRequest{}
	if err := ctx.Bind(req); err != nil {
		c.logger.ErrorF("Authorization bind error: %v", err)
		return nil, NewJsonResponse(ctx, BadRequest, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidRequest.ErrorCode,
			ErrorDescription: "Invalid request body",
		})
	}

	if req.Approved == nil {
		c.logger.ErrorF("Authorization approved error")
		return nil, NewJsonResponse(ctx, BadRequest, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidRequest.ErrorCode,
			ErrorDescription: "Missing approved",
		})
	}

	if err := SetJwtInfo(req, ctx); err != nil {
		c.logger.ErrorF("Authorization jwt token parse error: %v", err)
		return nil, NewErrorResponse(ctx, ErrParseParam)
	}

	return req, nil
}

var SuccessAuthorization = NewApiStatus("SUCCESS_AUTHORIZATION", "处理授权成功", Ok)

func (c *OAuth2Controller) PutAuthorization(ctx echo.Context) error {
	req, err := c.authorization(ctx)
	if err != nil {
		return err
	}

	res, redirectURI, code := c.oauth2Service.Authorization(req)

	if res == nil {
		uri, _ := url.Parse(redirectURI)
		query := uri.Query()
		query.Set("code", code.Code)
		if code.State != "" {
			query.Set("state", code.State)
		}
		uri.RawQuery = query.Encode()
		c.logger.InfoF("Authorization redirect to %s", uri.String())
		return NewApiResponse(SuccessAuthorization, uri.String()).Response(ctx)
	}

	if redirectURI != "" {
		uri := res.BuildErrorURL(redirectURI)
		c.logger.InfoF("Authorization redirect to %s", uri)
		return NewApiResponse(SuccessAuthorization, uri).Response(ctx)
	}

	return NewApiResponse(SuccessAuthorization, res).Response(ctx)
}

func (c *OAuth2Controller) GetAuthorization(ctx echo.Context) error {
	req, err := c.authorization(ctx)
	if err != nil {
		return err
	}

	res, redirectURI, code := c.oauth2Service.Authorization(req)

	if res == nil {
		uri, _ := url.Parse(redirectURI)
		query := uri.Query()
		query.Set("code", code.Code)
		if code.State != "" {
			query.Set("state", code.State)
		}
		uri.RawQuery = query.Encode()
		c.logger.InfoF("Authorization redirect to %s", uri.String())
		return ctx.Redirect(Found.Code(), uri.String())
	}

	if redirectURI != "" {
		uri := res.BuildErrorURL(redirectURI)
		c.logger.InfoF("Authorization redirect to %s", uri)
		return ctx.Redirect(Found.Code(), uri)
	}

	return NewJsonResponse(ctx, BadRequest, res)
}

func (c *OAuth2Controller) Token(ctx echo.Context) error {
	req := &TokenRequest{}
	if err := ctx.Bind(req); err != nil {
		c.logger.ErrorF("Token bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	res, err := c.oauth2Service.Token(req)

	if err != nil {
		return NewJsonResponse(ctx, BadRequest, err)
	}

	return NewJsonResponse(ctx, Ok, res)
}

func (c *OAuth2Controller) Revoke(ctx echo.Context) error {
	req := &RevokeRequest{}
	if err := ctx.Bind(req); err != nil {
		c.logger.ErrorF("Revoke bind error: %v", err)
		return NewJsonResponse(ctx, BadRequest, &OAuth2ErrorResponse{
			ErrorCode:        OAuth2ErrInvalidRequest.ErrorCode,
			ErrorDescription: "Invalid request body",
		})
	}

	if err := SetJwtInfo(req, ctx); err != nil {
		c.logger.ErrorF("Revoke jwt token parse error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}

	if err := c.oauth2Service.Revoke(req); err != nil {
		c.logger.ErrorF("Failed to revoke token: %v", err)
		return NewJsonResponse(ctx, BadRequest, err)
	}

	return ctx.NoContent(NoContent.Code())
}
