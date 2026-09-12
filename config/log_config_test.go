package config

import (
	"testing"

	"github.com/metacubex/mihomo/log"
)

func TestLogConfigAfterUpstreamSync(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want log.LogLevel
	}{
		{"default", "{}", log.INFO},
		{"nested", "log:\n  log-level: debug\n  log-path: logs/mihomo.log\n", log.DEBUG},
		{"top-level precedence", "log-level: warning\nlog:\n  log-level: debug\n", log.WARNING},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			general, err := parseGeneral(raw)
			if err != nil {
				t.Fatal(err)
			}
			if general.LogLevel != tc.want || general.Log.LogLevel != tc.want {
				t.Fatalf("log levels disagree: general=%v nested=%v want=%v", general.LogLevel, general.Log.LogLevel, tc.want)
			}
			if general.Log.MaxSize != 10 || general.Log.MaxAge != 3 || !general.Log.Compress {
				t.Fatalf("lost log rotation defaults: %+v", general.Log)
			}
			if tc.name == "nested" && general.Log.LogPath != "logs/mihomo.log" {
				t.Fatalf("lost log path: %q", general.Log.LogPath)
			}
		})
	}
}
