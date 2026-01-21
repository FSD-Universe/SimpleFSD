// Package controller
package controller

import (
	"fmt"
	"strings"

	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/labstack/echo/v4"
)

type MetarControllerInterface interface {
	QueryMetar(ctx echo.Context) error
}

type MetarController struct {
	logger       log.LoggerInterface
	metarService MetarServiceInterface
}

func NewMetarServiceController(
	logger log.LoggerInterface,
	metarService MetarServiceInterface,
) *MetarController {
	return &MetarController{
		logger:       log.NewLoggerAdapter(logger, "MetarController"),
		metarService: metarService,
	}
}

func (controller *MetarController) QueryMetar(ctx echo.Context) error {
	data := &RequestQueryMetar{}
	if err := ctx.Bind(data); err != nil {
		controller.logger.ErrorF("QueryMetar bind error: %v", err)
		return NewErrorResponse(ctx, ErrParseParam)
	}
	res := controller.metarService.QueryMetar(data)
	if data.Raw {
		if res.Data != nil {
			return TextResponse(ctx, res.HttpCode, fmt.Sprintf("<pre>%s</pre>", strings.Join(res.Data, "</pre>\b<pre>")))
		} else {
			return TextResponse(ctx, NotFound.Code(), "")
		}
	} else {
		return res.Response(ctx)
	}
}
