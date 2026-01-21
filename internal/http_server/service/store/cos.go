// Package store
// 存放 service.StoreServiceInterface 的实现
// 本文件存放腾讯云COS存储实现
package store

import (
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
	"github.com/tencentyun/cos-go-sdk-v5"
)

type TencentCosStoreService struct {
	logger            log.LoggerInterface
	localStore        StoreServiceInterface
	config            *config.HttpServerStore
	endpoint          *url.URL
	client            *cos.Client
	messageQueue      queue.MessageQueueInterface
	auditLogOperation operation.AuditLogOperationInterface
}

func NewTencentCosStoreService(
	logger log.LoggerInterface,
	config *config.HttpServerStore,
	localStore StoreServiceInterface,
	messageQueue queue.MessageQueueInterface,
	auditLogOperation operation.AuditLogOperationInterface,
) *TencentCosStoreService {
	service := &TencentCosStoreService{
		logger:            log.NewLoggerAdapter(logger, "TencentCosStoreService"),
		localStore:        localStore,
		config:            config,
		messageQueue:      messageQueue,
		auditLogOperation: auditLogOperation,
	}
	bucketUrl, _ := url.Parse(fmt.Sprintf("https://%s.cos.%s.myqcloud.com", config.Bucket, strings.ToLower(config.Region)))
	serviceUrl, _ := url.Parse(fmt.Sprintf("https://cos.%s.myqcloud.com", strings.ToLower(config.Region)))
	baseUrl := &cos.BaseURL{BucketURL: bucketUrl, ServiceURL: serviceUrl}
	service.client = cos.NewClient(baseUrl, &http.Client{
		Transport: &cos.AuthorizationTransport{
			SecretID:  config.AccessId,
			SecretKey: config.AccessKey,
		},
	})
	if config.CdnDomain != "" {
		service.endpoint, _ = url.Parse(config.CdnDomain)
	} else {
		service.endpoint = service.client.BaseURL.BucketURL
	}
	return service
}

func (store *TencentCosStoreService) GetStoreInfo(fileType FileType, fileLimit *config.HttpServerStoreFileLimit, file *multipart.FileHeader) (*StoreInfo, *ApiStatus) {
	return fileType.GenerateStoreInfo(fileLimit, file)
}

func (store *TencentCosStoreService) SaveFile(storeInfo *StoreInfo, file *multipart.FileHeader) *ApiStatus {
	if res := store.localStore.SaveFile(storeInfo, file); res != nil {
		return res
	}

	reader, err := file.Open()
	if err != nil {
		store.logger.ErrorF("TencentCosStoreService.SaveImageFile open form file errors: %v", err)
		return ErrFileUploadFail
	}

	_, err = store.client.Object.Put(context.Background(), storeInfo.RemotePath, reader, nil)
	if err != nil {
		store.logger.ErrorF("TencentCosStoreService.SaveImageFile upload image to remote storage error: %v", err)
		return ErrFileUploadFail
	}
	return nil
}

func (store *TencentCosStoreService) DeleteImageFile(file string) (*StoreInfo, error) {
	storeInfo, err := store.localStore.DeleteImageFile(file)
	if err != nil {
		return nil, err
	}

	return storeInfo, store.DeleteFile(storeInfo)
}

func (store *TencentCosStoreService) DeleteFile(storeInfo *StoreInfo) error {
	_, err := store.client.Object.Delete(context.Background(), storeInfo.RemotePath)
	if err != nil {
		store.logger.ErrorF("TencentCosStoreService.DeleteImageFile delete image from remote storage errors: %v", err)
		return err
	}
	return nil
}

func (store *TencentCosStoreService) SaveUploadImage(req *RequestUploadImage) *ApiResponse[*ResponseUploadImage] {
	storeInfo, res := store.GetStoreInfo(IMAGES, store.config.FileLimit.ImageLimit, req.File)
	if res != nil {
		return NewApiResponse[*ResponseUploadImage](res, nil)
	}

	if res := store.SaveFile(storeInfo, req.File); res != nil {
		return NewApiResponse[*ResponseUploadImage](res, nil)
	}

	accessUrl, err := url.JoinPath(store.endpoint.String(), storeInfo.RemotePath)
	if err != nil {
		return NewApiResponse[*ResponseUploadImage](ErrFilePathFail, nil)
	}

	store.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: store.auditLogOperation.NewAuditLog(
			operation.FileUpload,
			req.Cid,
			storeInfo.RemotePath,
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse(SuccessUploadFile, &ResponseUploadImage{
		FileSize:   req.File.Size,
		AccessPath: accessUrl,
	})
}

func (store *TencentCosStoreService) SaveUploadFile(req *RequestUploadFile) *ApiResponse[*ResponseUploadFile] {
	storeInfo, res := store.GetStoreInfo(FILES, store.config.FileLimit.FileLimit, req.File)
	if res != nil {
		return NewApiResponse[*ResponseUploadFile](res, nil)
	}

	if res := store.SaveFile(storeInfo, req.File); res != nil {
		return NewApiResponse[*ResponseUploadFile](res, nil)
	}

	accessUrl, err := url.JoinPath(store.endpoint.String(), storeInfo.RemotePath)
	if err != nil {
		return NewApiResponse[*ResponseUploadFile](ErrFilePathFail, nil)
	}

	store.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: store.auditLogOperation.NewAuditLog(
			operation.FileUpload,
			req.Cid,
			storeInfo.RemotePath,
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse(SuccessUploadFile, &ResponseUploadFile{
		FileSize:   req.File.Size,
		AccessPath: accessUrl,
	})
}
