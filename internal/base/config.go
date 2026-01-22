package base

import (
	"encoding/json"
	"errors"
	"os"

	. "github.com/half-nothing/simple-fsd/internal/interfaces/config"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

func readConfig(logger log.LoggerInterface) (*Config, *ValidResult) {
	config := DefaultConfig()

	// 读取配置文件
	if bytes, err := os.ReadFile(*global.ConfigFilePath); err != nil {
		// 如果配置文件不存在，创建默认配置
		if err := saveConfig(config); err != nil {
			return nil, ValidFailWith(errors.New("fail to save configuration file while creating configuration file"), err)
		}
		return nil, ValidFail(errors.New("the configuration file does not exist and has been created. Please try again after editing the configuration file"))
	} else if err := json.Unmarshal(bytes, config); err != nil {
		// 解析JSON配置
		return nil, ValidFailWith(errors.New("the configuration file does not contain valid JSON"), err)
	} else if result := config.CheckValid(logger); result.IsFail() {
		if result.OriginErr() != nil && errors.Is(result.OriginErr(), ErrVersionUnmatch) && *global.UpdateConfig {
			config.ConfigVersion = global.ConfigVersion
			if err := saveConfig(config); err != nil {
				return nil, ValidFailWith(errors.New("fail to save configuration file while creating configuration file"), err)
			}
			return readConfig(logger)
		} else {
			return nil, result
		}
	}
	return config, ValidPass()
}

func saveConfig(config *Config) error {
	if writer, err := os.OpenFile(*global.ConfigFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, global.DefaultFilePermissions); err != nil {
		return err
	} else if data, err := json.MarshalIndent(config, "", "\t"); err != nil {
		return err
	} else if _, err = writer.Write(data); err != nil {
		return err
	} else if err := writer.Close(); err != nil {
		return err
	}
	return nil
}

type Manager struct {
	config *utils.CachedValue[*Config]
	logger log.LoggerInterface
}

func NewManager(logger log.LoggerInterface) *Manager {
	manager := &Manager{
		logger: logger,
	}
	manager.config = utils.NewCachedValue(0, manager.getConfig)
	return manager
}

func (manager *Manager) getConfig() *Config {
	if config, result := readConfig(manager.logger); result != nil && result.IsFail() {
		manager.logger.Fatal(result.Err().Error())
		panic(result.OriginErr())
	} else {
		return config
	}
}

func (manager *Manager) Config() *Config {
	return manager.config.GetValue()
}

func (manager *Manager) SaveConfig() error {
	return saveConfig(manager.Config())
}
