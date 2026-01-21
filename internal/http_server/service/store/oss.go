// Package store
// 存放 service.StoreServiceInterface 的实现
// 本文件存放阿里云OSS存储实现
package store

import (
	"context"
	"mime/multipart"
	"net/url"
	"strings"

	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
)

type ALiYunOssStoreService struct {
	logger            log.LoggerInterface
	localStore        StoreServiceInterface
	config            *config.HttpServerStore
	endpoint          *url.URL
	client            *oss.Client
	messageQueue      queue.MessageQueueInterface
	auditLogOperation operation.AuditLogOperationInterface
}

func NewALiYunOssStoreService(
	logger log.LoggerInterface,
	config *config.HttpServerStore,
	localStore StoreServiceInterface,
	messageQueue queue.MessageQueueInterface,
	auditLogOperation operation.AuditLogOperationInterface,
) *ALiYunOssStoreService {
	service := &ALiYunOssStoreService{
		logger:            log.NewLoggerAdapter(logger, "ALiYunOssStoreService"),
		localStore:        localStore,
		config:            config,
		messageQueue:      messageQueue,
		auditLogOperation: auditLogOperation,
	}
	cfg := oss.LoadDefaultConfig().
		WithCredentialsProvider(credentials.NewStaticCredentialsProvider(config.AccessId, config.AccessKey)).
		WithRegion(config.Region).
		WithUseInternalEndpoint(config.UseInternalUrl)
	service.client = oss.NewClient(cfg)
	if config.CdnDomain != "" {
		service.endpoint, _ = url.Parse(config.CdnDomain)
	} else {
		service.endpoint, _ = url.Parse(strings.Replace(*cfg.Endpoint, "-internal", "", 1))
	}
	return service
}

func (store *ALiYunOssStoreService) GetStoreInfo(fileType FileType, fileLimit *config.HttpServerStoreFileLimit, file *multipart.FileHeader) (*StoreInfo, *ApiStatus) {
	return fileType.GenerateStoreInfo(fileLimit, file)
}

func (store *ALiYunOssStoreService) SaveFile(storeInfo *StoreInfo, file *multipart.FileHeader) *ApiStatus {
	if res := store.localStore.SaveFile(storeInfo, file); res != nil {
		return res
	}

	reader, err := file.Open()
	if err != nil {
		store.logger.ErrorF("SaveFile open form file error: %v", err)
		return ErrFileUploadFail
	}

	putRequest := &oss.PutObjectRequest{
		Bucket:       oss.Ptr(store.config.Bucket),
		Key:          oss.Ptr(storeInfo.RemotePath),
		StorageClass: oss.StorageClassStandard,
		Body:         reader,
	}

	_, err = store.client.PutObject(context.TODO(), putRequest)
	if err != nil {
		store.logger.ErrorF("SaveFile upload image to remote storage error: %v", err)
		return ErrFileUploadFail
	}
	return nil
}

func (store *ALiYunOssStoreService) DeleteFile(storeInfo *StoreInfo) error {
	delRequest := &oss.DeleteObjectRequest{
		Bucket: oss.Ptr(store.config.Bucket),
		Key:    oss.Ptr(storeInfo.RemotePath),
	}

	_, err := store.client.DeleteObject(context.TODO(), delRequest)
	if err != nil {
		store.logger.ErrorF("DeleteFile delete image from remote storage error: %v", err)
		return err
	}
	return nil
}

func (store *ALiYunOssStoreService) DeleteImageFile(file string) (*StoreInfo, error) {
	storeInfo, err := store.localStore.DeleteImageFile(file)
	if err != nil {
		return nil, err
	}

	return storeInfo, store.DeleteFile(storeInfo)
}

func (store *ALiYunOssStoreService) SaveUploadImage(req *RequestUploadImage) *ApiResponse[*ResponseUploadImage] {
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

func (store *ALiYunOssStoreService) SaveUploadFile(req *RequestUploadFile) *ApiResponse[*ResponseUploadFile] {
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
