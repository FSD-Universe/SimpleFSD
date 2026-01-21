// Package store
// 存放 service.StoreServiceInterface 的实现
// 本文件存放本地存储实现
package store

import (
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"

	"github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	. "github.com/half-nothing/simple-fsd/internal/interfaces/http/service"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/interfaces/operation"
	"github.com/half-nothing/simple-fsd/internal/interfaces/queue"
)

type LocalStoreService struct {
	logger            log.LoggerInterface
	config            *config.HttpServerStore
	messageQueue      queue.MessageQueueInterface
	auditLogOperation operation.AuditLogOperationInterface
}

func NewLocalStoreService(
	logger log.LoggerInterface,
	config *config.HttpServerStore,
	messageQueue queue.MessageQueueInterface,
	auditLogOperation operation.AuditLogOperationInterface,
) *LocalStoreService {
	return &LocalStoreService{
		logger:            log.NewLoggerAdapter(logger, "LocalStoreService"),
		config:            config,
		messageQueue:      messageQueue,
		auditLogOperation: auditLogOperation,
	}
}

func (store *LocalStoreService) DeleteImageFile(file string) (*StoreInfo, error) {
	storeInfo := NewStoreInfo(IMAGES, store.config.FileLimit.ImageLimit, nil)

	storeInfo.LocalAccessPath = filepath.Base(file)
	storeInfo.LocalPath = filepath.Join(store.config.FileLimit.ImageLimit.LocalRootPath, storeInfo.LocalAccessPath)
	storeInfo.RemotePath = strings.Replace(filepath.Join(store.config.FileLimit.ImageLimit.RemoteRootPath, storeInfo.LocalAccessPath), "\\", "/", -1)

	return storeInfo, store.DeleteFile(storeInfo)
}

func (store *LocalStoreService) GetStoreInfo(fileType FileType, fileLimit *config.HttpServerStoreFileLimit, file *multipart.FileHeader) (*StoreInfo, *ApiStatus) {
	return fileType.GenerateStoreInfo(fileLimit, file)
}

func (store *LocalStoreService) SaveFile(storeInfo *StoreInfo, file *multipart.FileHeader) *ApiStatus {
	if !storeInfo.StoreInServer {
		return nil
	}
	src, err := file.Open()
	defer func(src multipart.File) {
		_ = src.Close()
	}(src)
	if err != nil {
		store.logger.ErrorF("SaveFile open file error: %v", err)
		return ErrFileSaveFail
	}

	dst, err := os.OpenFile(storeInfo.LocalPath, os.O_WRONLY|os.O_CREATE, global.DefaultFilePermissions)
	defer func(dst *os.File) {
		_ = dst.Close()
	}(dst)
	if err != nil {
		store.logger.ErrorF("SaveFile create file error: %v", err)
		return ErrFileSaveFail
	}

	_, err = io.Copy(dst, src)
	if err != nil {
		store.logger.ErrorF("SaveFile copy file error: %v", err)
		return ErrFileSaveFail
	}
	return nil
}

func (store *LocalStoreService) DeleteFile(storeInfo *StoreInfo) error {
	if !storeInfo.StoreInServer {
		return nil
	}

	if err := os.Remove(storeInfo.LocalPath); err != nil {
		store.logger.ErrorF("DeleteFile remove file error: %v", err)
		return err
	}
	return nil
}

func (store *LocalStoreService) SaveUploadImage(req *RequestUploadImage) *ApiResponse[*ResponseUploadImage] {
	storeInfo, res := store.GetStoreInfo(IMAGES, store.config.FileLimit.ImageLimit, req.File)
	if res != nil {
		return NewApiResponse[*ResponseUploadImage](res, nil)
	}

	if res := store.SaveFile(storeInfo, req.File); res != nil {
		return NewApiResponse[*ResponseUploadImage](res, nil)
	}

	store.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: store.auditLogOperation.NewAuditLog(
			operation.FileUpload,
			req.Cid,
			storeInfo.LocalPath,
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse(SuccessUploadFile, &ResponseUploadImage{
		FileSize:   req.File.Size,
		AccessPath: storeInfo.LocalAccessPath,
	})
}

func (store *LocalStoreService) SaveUploadFile(req *RequestUploadFile) *ApiResponse[*ResponseUploadFile] {
	storeInfo, res := store.GetStoreInfo(FILES, store.config.FileLimit.FileLimit, req.File)
	if res != nil {
		return NewApiResponse[*ResponseUploadFile](res, nil)
	}

	if res := store.SaveFile(storeInfo, req.File); res != nil {
		return NewApiResponse[*ResponseUploadFile](res, nil)
	}

	store.messageQueue.Publish(&queue.Message{
		Type: queue.AuditLog,
		Data: store.auditLogOperation.NewAuditLog(
			operation.FileUpload,
			req.Cid,
			storeInfo.LocalPath,
			req.Ip,
			req.UserAgent,
			nil,
		),
	})

	return NewApiResponse(SuccessUploadFile, &ResponseUploadFile{
		FileSize:   req.File.Size,
		AccessPath: storeInfo.LocalAccessPath,
	})
}
