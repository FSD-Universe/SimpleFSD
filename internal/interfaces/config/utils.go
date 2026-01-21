// Package config
package config

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"github.com/half-nothing/simple-fsd/internal/interfaces/log"
	"github.com/half-nothing/simple-fsd/internal/utils"
)

var (
	ConfVersion, _ = newVersion(global.ConfigVersion)
	AppVersion, _  = newVersion(global.AppVersion)
)

func parseDuration(val string, target *time.Duration) error {
	duration, err := time.ParseDuration(val)
	if err != nil {
		return err
	}
	*target = duration
	return nil
}

func createFileWithContent(filePath string, content []byte) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, global.DefaultDirectoryPermission); err != nil {
		return err
	}

	return os.WriteFile(filePath, content, global.DefaultFilePermissions)
}

func cachedContent(logger log.LoggerInterface, filePath, url string) ([]byte, error) {
	if content, err := os.ReadFile(filePath); err == nil {
		return content, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("file read error: %w", err)
	}

	logger.InfoF("%s not found, downloading from %s", filePath, url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	logger.InfoF("Connection established with %s", url)

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response error: %w", err)
	}

	logger.InfoF("%s successfully downloaded, %d bytes", filePath, len(content))

	if err := createFileWithContent(filePath, content); err != nil {
		return nil, fmt.Errorf("file write error: %w", err)
	}

	return content, nil
}

func checkPort(port uint) *ValidResult {
	if port <= 0 {
		return ValidFail(errors.New("port must be greater than zero"))
	}
	if port > 65535 {
		return ValidFail(errors.New("port must be less than 65535"))
	}
	return ValidPass()
}

type checkVersionResult int

const (
	AllMatch checkVersionResult = iota
	MajorUnmatch
	MinorUnmatch
	PatchUnmatch
)

type Version struct {
	major   int
	minor   int
	patch   int
	version string
}

func newVersion(version string) (*Version, error) {
	versions := strings.Split(version, ".")
	if len(versions) < 3 {
		return nil, errors.New("invalid version String")
	}
	return &Version{
		major:   utils.StrToInt(versions[0], 0),
		minor:   utils.StrToInt(versions[1], 0),
		patch:   utils.StrToInt(versions[2], 0),
		version: version,
	}, nil
}

func (v *Version) checkVersion(version *Version) checkVersionResult {
	if v.major != version.major {
		return MajorUnmatch
	}
	if v.minor != version.minor {
		return MinorUnmatch
	}
	if v.patch != version.patch {
		return PatchUnmatch
	}
	return AllMatch
}

func (v *Version) String() string {
	return v.version
}
