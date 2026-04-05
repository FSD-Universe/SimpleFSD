// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package service
package service

import (
	"fmt"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces"
	"github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
)

type SoftwareService struct {
	logger        log.LoggerInterface
	metaOperation operation.MetaOperationInterface
	softwareCache interfaces.CacheInterface[*service.ResponseGetSoftware]
}

func NewSoftwareService(
	logger log.LoggerInterface,
	metaOperation operation.MetaOperationInterface,
	softwareCache interfaces.CacheInterface[*service.ResponseGetSoftware],
) *SoftwareService {
	return &SoftwareService{
		logger:        log.NewLoggerAdapter(logger, "SoftwareService"),
		metaOperation: metaOperation,
		softwareCache: softwareCache,
	}
}

func (softwareService *SoftwareService) GetSoftware(req *service.RequestGetSoftware) *service.ApiResponse[*service.ResponseGetSoftware] {
	val, ok := softwareService.softwareCache.Get(req.Name)
	if ok {
		if val == nil {
			return service.NewApiResponse[*service.ResponseGetSoftware](service.ErrSoftwareNotFound, nil)
		}
		return service.NewApiResponse(service.SuccessGetSoftware, val)
	}
	versionKey := fmt.Sprintf("software_%s_version", req.Name)
	downloadUrlKey := fmt.Sprintf("software_%s_download_url", req.Name)
	sha256Key := fmt.Sprintf("software_%s_sha256", req.Name)
	version, err := softwareService.metaOperation.GetMeta(versionKey)
	if err != nil {
		softwareService.softwareCache.SetWithTTL(req.Name, nil, time.Hour)
		return service.NewApiResponse[*service.ResponseGetSoftware](service.ErrSoftwareNotFound, nil)
	}
	downloadUrl, err := softwareService.metaOperation.GetMeta(downloadUrlKey)
	if err != nil {
		softwareService.softwareCache.SetWithTTL(req.Name, nil, time.Hour)
		return service.NewApiResponse[*service.ResponseGetSoftware](service.ErrSoftwareNotFound, nil)
	}
	sha256, err := softwareService.metaOperation.GetMeta(sha256Key)
	if err != nil {
		softwareService.softwareCache.SetWithTTL(req.Name, nil, time.Hour)
		return service.NewApiResponse[*service.ResponseGetSoftware](service.ErrSoftwareNotFound, nil)
	}
	val = &service.ResponseGetSoftware{
		Version:     version.Value,
		DownloadUrl: downloadUrl.Value,
		Sha256:      sha256.Value,
	}
	softwareService.softwareCache.SetWithTTL(req.Name, val, time.Hour)
	return service.NewApiResponse(service.SuccessGetSoftware, val)
}

func (softwareService *SoftwareService) FlushSoftwareCache(req *service.RequestFlushSoftwareCache) *service.ApiResponse[bool] {
	res := service.CheckPermission[bool](req.Permission, operation.SoftwareFlush)
	if res != nil {
		return res
	}
	softwareService.softwareCache.Del(req.Name)
	return service.NewApiResponse(service.SuccessFlushSoftware, true)
}
