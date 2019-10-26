package main

import (
	"github.com/json-iterator/go"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"arvancloud/redins/handler"
	"github.com/coredns/coredns/request"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	"github.com/miekg/dns"
)

var (
	s []dns.Server
	h *handler.DnsRequestHandler
	l *handler.RateLimiter
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	// log.Printf("[DEBUG] handle request")
	state := request.Request{W: w, Req: r}

	if l.CanHandle(state.IP()) {
		h.HandleRequest(&state)
	} else {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeRefused)
		state.W.WriteMsg(msg)
	}
}

type RedinsConfig struct {
	Server    []handler.ServerConfig    `json:"server,omitempty"`
	ErrorLog  logger.LogConfig          `json:"error_log,omitempty"`
	Handler   handler.HandlerConfig     `json:"handler,omitempty"`
	RateLimit handler.RateLimiterConfig `json:"ratelimit,omitempty"`
}

func LoadConfig(path string) *RedinsConfig {
	config := &RedinsConfig{
		Server: []handler.ServerConfig{
			{
				Ip:       "127.0.0.1",
				Port:     1053,
				Protocol: "udp",
			},
		},
		Handler: handler.HandlerConfig{
			Upstream: []handler.UpstreamConfig{
				{
					Ip:       "1.1.1.1",
					Port:     53,
					Protocol: "udp",
					Timeout:  400,
				},
			},
			GeoIp: handler.GeoIpConfig{
				Enable:    false,
				CountryDB: "geoCity.mmdb",
				ASNDB:     "geoIsp.mmdb",
			},
			HealthCheck: handler.HealthcheckConfig{
				Enable:             false,
				MaxRequests:        10,
				MaxPendingRequests: 100,
				UpdateInterval:     600,
				CheckInterval:      600,
				RedisStatusServer: uperdis.RedisConfig{
					Ip:                "127.0.0.1",
					Port:              6379,
					DB:                0,
					Password:          "",
					Prefix:            "redins_",
					Suffix:            "_redins",
					Connection: uperdis.RedisConnectionConfig{
						MaxIdleConnections:   10,
						MaxActiveConnections: 10,
						ConnectTimeout:       500,
						ReadTimeout:          500,
						IdleKeepAlive:        30,
						MaxKeepAlive:         0,
						WaitForConnection:    false,
					},
				},
				Log: logger.LogConfig{
					Enable:     true,
					Target:     "file",
					Level:      "info",
					Path:       "/tmp/healthcheck.log",
					Format:     "json",
					TimeFormat: time.RFC3339,
					Sentry: logger.SentryConfig{
						Enable: false,
					},
					Syslog: logger.SyslogConfig{
						Enable: false,
					},
				},
			},
			MaxTtl:            3600,
			CacheTimeout:      60,
			ZoneReload:        600,
			LogSourceLocation: false,
			UpstreamFallback:  false,
			Redis: uperdis.RedisConfig{
				Ip:                "127.0.0.1",
				Port:              6379,
				DB:                0,
				Password:          "",
				Prefix:            "redins_",
				Suffix:            "_redins",
				Connection: uperdis.RedisConnectionConfig{
					MaxIdleConnections:   10,
					MaxActiveConnections: 10,
					ConnectTimeout:       500,
					ReadTimeout:          500,
					IdleKeepAlive:        30,
					MaxKeepAlive:         0,
					WaitForConnection:    false,
				},
			},
			Log: logger.LogConfig{
				Enable:     true,
				Target:     "file",
				Level:      "info",
				Path:       "/tmp/redins.log",
				Format:     "json",
				TimeFormat: time.RFC3339,
				Sentry: logger.SentryConfig{
					Enable: false,
				},
				Syslog: logger.SyslogConfig{
					Enable: false,
				},
			},
		},
		ErrorLog: logger.LogConfig{
			Enable:     true,
			Target:     "stdout",
			Level:      "info",
			Format:     "text",
			TimeFormat: time.RFC3339,
			Sentry: logger.SentryConfig{
				Enable: false,
			},
			Syslog: logger.SyslogConfig{
				Enable: false,
			},
		},
		RateLimit: handler.RateLimiterConfig{
			Enable:    false,
			Rate:      60,
			Burst:     10,
			BlackList: []string{},
			WhiteList: []string{},
		},
	}
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("[ERROR] cannot load file %s : %s", path, err)
		log.Printf("[INFO] loading default config")
		return config
	}
	err = jsoniter.Unmarshal(raw, config)
	if err != nil {
		log.Printf("[ERROR] cannot load json file")
		log.Printf("[INFO] loading default config")
		return config
	}
	return config
}

func Start() {
	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	cfg := LoadConfig(configFile)

	logger.Default = logger.NewLogger(&cfg.ErrorLog, nil)

	s = handler.NewServer(cfg.Server)

	h = handler.NewHandler(&cfg.Handler)

	l = handler.NewRateLimiter(&cfg.RateLimit)

	dns.HandleFunc(".", handleRequest)

	for i := range s {
		go s[i].ListenAndServe()
		time.Sleep(1 * time.Second)
	}
}

func Stop() {
	for i := range s {
		s[i].Shutdown()
	}
	h.ShutDown()
}

func main() {

	Start()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGHUP)

	for sig := range c {
		switch sig {
		case syscall.SIGINT:
			Stop()
			return
		case syscall.SIGHUP:
			Stop()
			Start()
		}
	}
}
