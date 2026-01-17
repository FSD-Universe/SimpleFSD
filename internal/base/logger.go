package base

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/half-nothing/simple-fsd/internal/interfaces/global"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	LevelFatal slog.Level = 12
)

type AsyncHandler struct {
	ch       chan []byte
	logName  string
	writer   io.Writer
	attrs    []slog.Attr
	group    string
	logLevel slog.Level
	wg       sync.WaitGroup
}

func NewAsyncHandler(logPath, logName string, logLevel slog.Level, noLogs bool) *AsyncHandler {
	h := &AsyncHandler{
		ch:       make(chan []byte, 1<<16), // 64KB
		logLevel: logLevel,
		logName:  strings.ToUpper(logName),
	}
	if noLogs {
		h.writer = os.Stdout
	} else {
		h.writer = io.MultiWriter(os.Stdout, &lumberjack.Logger{
			Filename:   logPath, // 日志文件的位置
			MaxSize:    10,      // 文件最大尺寸（以MB为单位）
			MaxBackups: 30,      // 保留的最大旧文件数量
			MaxAge:     28,      // 保留旧文件的最大天数
			Compress:   true,    // 是否压缩/归档旧文件
			LocalTime:  true,    // 使用本地时间创建时间戳
		})
	}
	go h.startWorker()
	return h
}

func (h *AsyncHandler) startWorker() {
	h.wg.Add(1)
	defer h.wg.Done()
	for data := range h.ch {
		_, _ = h.writer.Write(data)
	}
}

func (h *AsyncHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.logLevel
}

func (h *AsyncHandler) Handle(_ context.Context, r slog.Record) error {
	level := r.Level.String()

	switch r.Level {
	case slog.LevelDebug:
		level = color.MagentaString(level)
	case slog.LevelInfo:
		level = color.BlueString(level)
	case slog.LevelWarn:
		level = color.YellowString(level)
	case slog.LevelError:
		level = color.RedString(level)
	case LevelFatal:
		level = color.HiRedString("FATAL")
	}

	// 时间 | 记录器 | 级别 | 消息
	line := fmt.Sprintf(
		"%s | %-5s | %-5s | %s",
		color.GreenString(r.Time.Format("2006-01-02T15:04:05")),
		h.logName,
		level,
		color.CyanString(r.Message),
	)

	for _, attr := range h.attrs {
		line += color.CyanString(fmt.Sprintf(" %s=%v", attr.Key, attr.Value))
	}

	r.Attrs(func(attr slog.Attr) bool {
		line += color.CyanString(fmt.Sprintf(" %s=%v", attr.Key, attr.Value))
		return true
	})

	line += "\n"

	h.Write([]byte(line))
	return nil
}

func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// 合并新旧字段
	newAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	newAttrs = append(newAttrs, h.attrs...)
	newAttrs = append(newAttrs, attrs...)

	return &AsyncHandler{
		writer:   h.writer,
		attrs:    newAttrs,
		group:    h.group,
		logLevel: h.logLevel,
	}
}

func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	// 记录当前分组名称
	return &AsyncHandler{
		writer:   h.writer,
		attrs:    h.attrs,
		group:    name,
		logLevel: h.logLevel,
	}
}

func (h *AsyncHandler) Write(p []byte) {
	// 拷贝数据避免竞态
	pb := make([]byte, len(p))
	copy(pb, p)
	h.ch <- pb
}

func (h *AsyncHandler) Close() error {
	close(h.ch)
	h.wg.Wait()
	if f, ok := h.writer.(*os.File); ok {
		_ = f.Sync()
	}
	return nil
}

type ShutdownCallback struct {
	handler *AsyncHandler
}

func (lc *ShutdownCallback) Invoke(_ context.Context) error {
	return lc.handler.Close()
}

func NewLogger() *Logger {
	return &Logger{
		logger:           nil,
		shutdownCallback: nil,
	}
}

type Logger struct {
	handler          *AsyncHandler
	logger           *slog.Logger
	shutdownCallback *ShutdownCallback
}

func (lg *Logger) Init(logPath, logName string, debug, noLogs bool) {
	lg.handler = NewAsyncHandler(logPath, logName, slog.LevelInfo, noLogs)
	if debug {
		lg.handler.logLevel = slog.LevelDebug
	}
	lg.logger = slog.New(lg.handler)
	lg.shutdownCallback = &ShutdownCallback{handler: lg.handler}
	lg.DebugF("%s logger initialized", strings.ToUpper(logName))
}

func (lg *Logger) ShutdownCallback() global.Callable {
	return lg.shutdownCallback
}

func (lg *Logger) LogHandler() *slog.Logger {
	return lg.logger
}

func (lg *Logger) Debug(msg string) {
	lg.logger.Debug(msg)
}

func (lg *Logger) DebugF(msg string, v ...interface{}) {
	lg.logger.Debug(fmt.Sprintf(msg, v...))
}

func (lg *Logger) Info(msg string) {
	lg.logger.Info(msg)
}

func (lg *Logger) InfoF(msg string, v ...interface{}) {
	lg.logger.Info(fmt.Sprintf(msg, v...))
}

func (lg *Logger) Warn(msg string) {
	lg.logger.Warn(msg)
}

func (lg *Logger) WarnF(msg string, v ...interface{}) {
	lg.logger.Warn(fmt.Sprintf(msg, v...))
}

func (lg *Logger) Error(msg string) {
	lg.logger.Error(msg)
}

func (lg *Logger) ErrorF(msg string, v ...interface{}) {
	lg.logger.Error(fmt.Sprintf(msg, v...))
}

func (lg *Logger) Fatal(msg string) {
	lg.logger.Log(context.Background(), LevelFatal, msg)
}

func (lg *Logger) FatalF(msg string, v ...interface{}) {
	lg.logger.Log(context.Background(), LevelFatal, fmt.Sprintf(msg, v...))
}
