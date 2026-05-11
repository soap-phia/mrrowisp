package wisp

import (
	"log"
	"strings"
)

type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

type logLevel int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarn
	levelError
)

type Log struct {
	level logLevel
	inner *log.Logger
}

func newLogger(level string) Logger {
	lvl := levelInfo
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = levelDebug
	case "info":
		lvl = levelInfo
	case "warn", "warning":
		lvl = levelWarn
	case "error":
		lvl = levelError
	}
	return &Log{level: lvl, inner: log.Default()}
}

func (l *Log) Debug(msg string, kv ...any) { l.log(levelDebug, "DEBUG", msg, kv...) }
func (l *Log) Info(msg string, kv ...any)  { l.log(levelInfo, "INFO", msg, kv...) }
func (l *Log) Warn(msg string, kv ...any)  { l.log(levelWarn, "WARN", msg, kv...) }
func (l *Log) Error(msg string, kv ...any) { l.log(levelError, "ERROR", msg, kv...) }

func (l *Log) log(lvl logLevel, prefix string, msg string, kv ...any) {
	if l == nil || l.inner == nil || lvl < l.level {
		return
	}
	if len(kv) == 0 {
		l.inner.Printf("[%s] %s", prefix, msg)
		return
	}
	l.inner.Printf("[%s] %s %v", prefix, msg, kv)
}
