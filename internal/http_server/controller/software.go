// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package controller
package controller

import (
	"github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/labstack/echo/v4"
)

type SoftwareControllerInterface interface {
	GetSoftware(ctx echo.Context) error
	FlushSoftwareCache(ctx echo.Context) error
}

type SoftwareController struct {
	logger          log.LoggerInterface
	softwareService service.SoftwareServiceInterface
}

func NewSoftwareController(
	lg log.LoggerInterface,
	softwareService service.SoftwareServiceInterface,
) *SoftwareController {
	return &SoftwareController{
		logger:          log.NewLoggerAdapter(lg, "SoftwareController"),
		softwareService: softwareService,
	}
}

func (control *SoftwareController) GetSoftware(ctx echo.Context) error {
	data := &service.RequestGetSoftware{}
	if err := ctx.Bind(data); err != nil {
		control.logger.ErrorF("GetSoftware bind error: %v", err)
		return service.NewErrorResponse(ctx, service.ErrParseParam)
	}
	return control.softwareService.GetSoftware(data).Response(ctx)
}

func (control *SoftwareController) FlushSoftwareCache(ctx echo.Context) error {
	data := &service.RequestFlushSoftwareCache{}
	if err := ctx.Bind(data); err != nil {
		control.logger.ErrorF("FlushSoftwareCache bind error: %v", err)
		return service.NewErrorResponse(ctx, service.ErrParseParam)
	}
	if err := SetJwtInfo(data, ctx); err != nil {
		control.logger.ErrorF("FlushSoftwareCache jwt token parse error: %v", err)
		return service.NewErrorResponse(ctx, service.ErrParseParam)
	}
	return control.softwareService.FlushSoftwareCache(data).Response(ctx)
}
