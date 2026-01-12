// Package service
package service

import (
	"strings"

	"github.com/half-nothing/simple-fsd/internal/interfaces"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

type MetarService struct {
	logger       log.LoggerInterface
	metarManager interfaces.MetarManagerInterface
}

func NewMetarService(
	logger log.LoggerInterface,
	metarManager interfaces.MetarManagerInterface,
) *MetarService {
	return &MetarService{
		logger:       log.NewLoggerAdapter(logger, "MetarService"),
		metarManager: metarManager,
	}
}

func (metarService *MetarService) QueryMetar(req *RequestQueryMetar) *ApiResponse[ResponseQueryMetar] {
	if req.ICAO == "" {
		return NewApiResponse[ResponseQueryMetar](ErrIllegalParam, nil)
	}

	icaos := strings.Split(req.ICAO, ",")
	if len(icaos) < 1 {
		return NewApiResponse[ResponseQueryMetar](ErrIllegalParam, nil)
	}

	icaos = utils.Map[string](icaos, func(element string) string { return strings.TrimSpace(element) })
	metars := metarService.metarManager.QueryMetars(icaos)
	if len(metars) < 1 {
		return NewApiResponse[ResponseQueryMetar](ErrMetarNotFound, nil)
	}
	data := ResponseQueryMetar(metars)
	return NewApiResponse(SuccessGetMetar, &data)
}
