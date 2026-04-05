// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package service
package service

var (
	ErrSoftwareNotFound  = NewApiStatus("SOFTWARE_NOT_FOUND", "软件不存在", NotFound)
	SuccessGetSoftware   = NewApiStatus("GET_SOFTWARE", "获取软件成功", Ok)
	SuccessFlushSoftware = NewApiStatus("FLUSH_SOFTWARE", "刷新软件缓存成功", Ok)
)

type SoftwareServiceInterface interface {
	GetSoftware(req *RequestGetSoftware) *ApiResponse[*ResponseGetSoftware]
	FlushSoftwareCache(req *RequestFlushSoftwareCache) *ApiResponse[bool]
}

type RequestGetSoftware struct {
	Name string `param:"name"`
}

type ResponseGetSoftware struct {
	Version     string `json:"version"`
	DownloadUrl string `json:"download_url"`
	Sha256      string `json:"sha256"`
}

type RequestFlushSoftwareCache struct {
	JwtHeader
	Name string `param:"name"`
}
