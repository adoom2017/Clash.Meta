package log

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/common/observable"
	"gopkg.in/natefinch/lumberjack.v2"

	log "github.com/sirupsen/logrus"
)

var (
	logCh      = make(chan Event)
	source     = observable.NewObservable[Event](logCh)
	level      = INFO
	filename   = ""
	maxSize    = 10
	maxAge     = 3
	maxBackups = 10
	compress   = true
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.999999999Z07:00",
		EnvironmentOverrideColors: true,
	})
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	event := newLog(INFO, format, v...)
	logCh <- event
	print(event)
}

func Warnln(format string, v ...any) {
	event := newLog(WARNING, format, v...)
	logCh <- event
	print(event)
}

func Errorln(format string, v ...any) {
	event := newLog(ERROR, format, v...)
	logCh <- event
	print(event)
}

func Debugln(format string, v ...any) {
	event := newLog(DEBUG, format, v...)
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

func Subscribe() observable.Subscription[Event] {
	sub, _ := source.Subscribe()
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return level
}

func Path() string {
	return filename
}

func Size() int {
	return maxSize
}

func Age() int {
	return maxAge
}

func Backups() int {
	return maxBackups
}

func Compress() bool {
	return compress
}

func SetLevel(newLevel LogLevel) {
	level = newLevel
}

func SetOutput(path string, size int, age int, backups int, comp bool) {
	dir := filepath.Dir(path)

	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			log.Errorf("Failed to create dir: %s, err: %v", dir, err)
			return
		}
	}

	filename = path
	maxSize = size
	maxAge = age
	maxBackups = backups
	compress = comp

	log.SetOutput(&lumberjack.Logger{
		Filename:   filename,
		MaxSize:    maxSize,
		MaxAge:     maxAge,
		MaxBackups: maxBackups,
		Compress:   compress,
	})
}

func print(data Event) {
	if data.LogLevel < level {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
