package main

import (
	"github.com/json-iterator/go"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"arvancloud/redins/handler"
	"github.com/coredns/coredns/request"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	"github.com/miekg/dns"
	_ "net/http/pprof"
)

var (
	s []dns.Server
	h *handler.DnsRequestHandler
	l *handler.RateLimiter
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	state := request.Request{W: w, Req: r}
	logger.Default.Debugf("handle request: [%d] %s %s", r.Id, state.Name(), state.Type())

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
					Address:           "127.0.0.1:6379",
					Net:               "tcp",
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
					Kafka: logger.KafkaConfig{
						Enable:      false,
						Topic:       "redins",
						Brokers:     []string{"127.0.0.1:9092"},
						Format:      "json",
						Compression: "none",
						Timeout:     3000,
						BufferSize:  1000,
					},
				},
			},
			MaxTtl:            3600,
			CacheTimeout:      60,
			ZoneReload:        600,
			LogSourceLocation: false,
			UpstreamFallback:  false,
			Redis: uperdis.RedisConfig{
				Address:           "127.0.0.1:6379",
				Net:               "tcp",
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
				Kafka: logger.KafkaConfig{
					Enable:      false,
					Topic:       "redins",
					Brokers:     []string{"127.0.0.1:9092"},
					Format:      "json",
					Compression: "none",
					Timeout:     3000,
					BufferSize:  1000,
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
			Kafka: logger.KafkaConfig{
				Enable:      false,
				Topic:       "redins",
				Brokers:     []string{"127.0.0.1:9092"},
				Format:      "json",
				Compression: "none",
				Timeout:     3000,
				BufferSize:  1000,
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
	log.Printf("[INFO] loading config : %s", configFile)
	cfg := LoadConfig(configFile)

	log.Printf("[INFO] loading logger...")
	logger.Default = logger.NewLogger(&cfg.ErrorLog, nil)
	log.Printf("[INFO] logger loaded")

	s = handler.NewServer(cfg.Server)

	logger.Default.Info("starting handler...")
	h = handler.NewHandler(&cfg.Handler)
	logger.Default.Info("handler started")

	l = handler.NewRateLimiter(&cfg.RateLimit)

	dns.HandleFunc(".", handleRequest)

	logger.Default.Info("binding listeners...")
	for i := range s {
		go func(i int) {
			err := s[i].ListenAndServe()
			if err != nil {
				logger.Default.Errorf("listener error : %s", err)
			}
		}(i)
	}
	logger.Default.Info("binding completed")
}

func Stop() {
	for i := range s {
		s[i].Shutdown()
	}
	h.ShutDown()
}

func main() {

	Start()

	// TODO: this should be part of a general api
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

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
