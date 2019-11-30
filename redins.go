package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/Shopify/sarama"
	"github.com/getsentry/raven-go"
	"github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"
	"github.com/oschwald/maxminddb-golang"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"arvancloud/redins/handler"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	"github.com/miekg/dns"
	_ "net/http/pprof"
)

var (
	s          []dns.Server
	h          *handler.DnsRequestHandler
	l          *handler.RateLimiter
	configFile string
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	context := handler.NewRequestContext(w, r)
	logger.Default.Debugf("handle request: [%d] %s %s", r.Id, context.Name(), context.Type())

	if l.CanHandle(context.IP()) {
		h.HandleRequest(context)
	} else {
		context.Response(dns.RcodeRefused)
	}
}

type RedinsConfig struct {
	Server    []handler.ServerConfig    `json:"server,omitempty"`
	ErrorLog  logger.LogConfig          `json:"error_log,omitempty"`
	Handler   handler.HandlerConfig     `json:"handler,omitempty"`
	RateLimit handler.RateLimiterConfig `json:"ratelimit,omitempty"`
}

func LoadConfig(path string) (*RedinsConfig, error) {
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
					Address:  "127.0.0.1:6379",
					Net:      "tcp",
					DB:       0,
					Password: "",
					Prefix:   "redins_",
					Suffix:   "_redins",
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
			Redis: uperdis.RedisConfig{
				Address:  "127.0.0.1:6379",
				Net:      "tcp",
				DB:       0,
				Password: "",
				Prefix:   "redins_",
				Suffix:   "_redins",
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
	configFile, err  := os.Open(path)
	if err != nil {
		log.Printf("[ERROR] cannot load file %s : %s", path, err)
		log.Printf("[INFO] loading default config")
		return config, err
	}
	decoder := jsoniter.NewDecoder(configFile)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(config)
	if err != nil {
		log.Printf("[ERROR] cannot load json file")
		log.Printf("[INFO] loading default config")
		return config, err
	}
	return config, nil
}

func Start() {
	log.Printf("[INFO] loading config : %s", configFile)
	cfg, _ := LoadConfig(configFile)

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
		_ = s[i].Shutdown()
	}
	h.ShutDown()
}

func Verify(configFile string) {
	ok := aurora.Bold(aurora.Green("[ OK ]"))
	fail := aurora.Bold(aurora.Red("[FAIL]"))
	warn := aurora.Bold(aurora.Yellow("[WARN]"))
	printResult := func(msg string, err error) {
		if err == nil {
			fmt.Printf("%-60s%s\n", msg, ok)
			return
		} else {
			fmt.Printf("%-60s%s : %s\n", msg, fail, err)
		}
	}
	printWarning := func(msg string, warning string) {
		fmt.Printf("%-60s%s : %s\n", msg, warn, warning)
	}

	checkAddress := func(protocol string, ip string, port int) {
		msg := fmt.Sprintf("checking protocol : %s", protocol)
		var err error = nil
		if protocol != "tcp" && protocol != "udp" {
			err = errors.New("invalid protocol")
		}
		printResult(msg, err)

		msg = fmt.Sprintf("checking ip address : %s", ip)
		err = nil
		if ip := net.ParseIP(ip); ip == nil {
			err = errors.New("invalid ip address")
		}
		printResult(msg, err)

		msg = fmt.Sprintf("checking port number : %d", port)
		err = nil
		if port > 65535 || port < 1 {
			err = errors.New("invalid port number")
		}
		printResult(msg, err)
	}

	checkRedis := func(config *uperdis.RedisConfig) {
		fmt.Println("checking redis...")
		rd := uperdis.NewRedis(config)
		msg := fmt.Sprintf("checking whether %s://%s is available", config.Net, config.Address)
		err := rd.Ping()
		printResult(msg, err)
		msg = fmt.Sprintf("checking notify-keyspace-events")
		err = nil
		var nkse string
		nkse, err = rd.GetConfig("notify-keyspace-events")
		if err == nil {
			if !strings.Contains(nkse, "K") {
				err = errors.New("keyspace in not active")
			} else if !strings.Contains(nkse, "A") && !strings.Contains(nkse, "s") {
				err = errors.New("A or s should be active")
			}
		}
		printResult(msg, err)
	}

	checkLog := func(config *logger.LogConfig) {
		fmt.Println("checking log...")
		msg := fmt.Sprintf("checking target : %s", config.Path)
		var err error = nil
		if config.Target != "stdout" && config.Target != "stderr" && config.Target != "file" && config.Target != "udp" {
			err = errors.New("invalid target : " + config.Target)
		}
		printResult(msg, err)

		if config.Target == "file" {
			msg = fmt.Sprintf("checking file target : %s", config.Path)
			var file *os.File
			file, err = os.OpenFile(config.Target, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
			if err == nil {
				file.Close()
			}
			printResult(msg, err)
		}
		if config.Target == "udp" {
			msg = fmt.Sprintf("checking udp target : %s", config.Target)
			err = nil
			var raddr *net.UDPAddr
			raddr, err = net.ResolveUDPAddr("udp", config.Path)
			if err == nil {
				var con *net.UDPConn
				con, err = net.DialUDP("udp", nil, raddr)
				if err == nil {
					con.Close()
				}
			}
			printResult(msg, err)
		}

		msg = fmt.Sprintf("checking log level : %s", config.Level)
		err = nil
		if config.Level != "debug" && config.Level != "info" && config.Level != "warning" && config.Level != "error" {
			err = errors.New("invalid log level : " + config.Level)
		}
		printResult(msg, err)

		msg = fmt.Sprintf("checking format : %s", config.Format)
		err = nil
		if config.Format != "text" && config.Format != "json" && config.Format != "capnp_request" {
			err = errors.New("invalid log format : " + config.Format)
		}
		printResult(msg, err)

		msg = fmt.Sprintf("checking time format : %s", config.TimeFormat)
		err = nil
		t1, _ := time.Parse(time.RFC3339, time.RFC3339)
		timeStr := t1.Format(config.TimeFormat)
		var t2 time.Time
		t2, err = time.Parse(config.TimeFormat, timeStr)
		if err == nil {
			if t2 != t1 {
				err = errors.New("invalid time format")
			}
		}
		printResult(msg, err)

		if config.Kafka.Enable {
			fmt.Println("checking kafka at ", config.Kafka.Brokers)
			msg = fmt.Sprintf("checking kafka")
			err = nil
			cfg := sarama.NewConfig()
			cfg.Producer.RequiredAcks = sarama.WaitForAll
			cfg.Producer.Compression = sarama.CompressionNone
			cfg.Producer.Flush.Frequency = 500 * time.Millisecond
			cfg.Producer.Return.Errors = true
			cfg.Producer.Return.Successes = true

			cfg.Metadata.Timeout = time.Duration(config.Kafka.Timeout) * time.Millisecond

			var producer sarama.SyncProducer
			producerMessages := []*sarama.ProducerMessage{
				{
					Topic:    config.Kafka.Topic,
					Value:    sarama.StringEncoder("test message"),
					Metadata: "test",
				},
			}
			producer, err = sarama.NewSyncProducer(config.Kafka.Brokers, cfg)
			if err == nil {
				err = producer.SendMessages(producerMessages)
			}
			printResult(msg, err)
		}
		if config.Sentry.Enable {
			msg = fmt.Sprintf("checking sentry at %s", config.Sentry.DSN)
			err = nil
			var client *raven.Client
			client, err = raven.New(config.Sentry.DSN)
			if err == nil {
				packet := raven.NewPacket("test message", nil)
				eventID, ch := client.Capture(packet, nil)
				if eventID != "" {
					err = <-ch
				}
				if err == nil && eventID == "" {
					err = errors.New("sentry test failed")
				}
			}
			printResult(msg, err)
		}
		if config.Syslog.Enable {
			msg = fmt.Sprintf("checking syslog at %s", config.Syslog.Address)
			var w *syslog.Writer
			w, err = syslog.Dial(config.Syslog.Protocol, config.Syslog.Address, syslog.LOG_ERR, "syslog test")
			if err == nil {
				err = w.Err("test message")
			}
			printResult(msg, err)
		}
	}

	fmt.Println("Starting Config Verification")

	msg := fmt.Sprintf("loading config file : %s", configFile)
	config, err := LoadConfig(configFile)
	printResult(msg, err)

	fmt.Println("checking listeners...")
	for _, server := range config.Server {
		checkAddress(server.Protocol, server.Ip, server.Port)
		msg = fmt.Sprintf("checking port number : %d", server.Port)
		if server.Port != 53 {
			printWarning(msg, "using non-standard port")
		} else {
			printResult(msg, nil)
		}

		address := server.Ip + ":" + strconv.Itoa(server.Port)
		msg = fmt.Sprintf("checking whether %s://%s is available", server.Protocol, address)
		err = nil
		if server.Protocol == "udp" {
			var ln net.PacketConn
			ln, err = net.ListenPacket(server.Protocol, address)
			if err == nil {
				_ = ln.Close()
			}
		} else {
			var ln net.Listener
			ln, err = net.Listen(server.Protocol, address)
			if err == nil {
				_ = ln.Close()
			}
		}
		printResult(msg, err)
	}
	fmt.Println("checking upstreams...")
	for _, upstream := range config.Handler.Upstream {
		checkAddress(upstream.Protocol, upstream.Ip, upstream.Port)
		address := upstream.Ip + ":" + strconv.Itoa(upstream.Port)
		msg = fmt.Sprintf("checking whether %s://%s is available", upstream.Protocol, address)
		err = nil
		client := &dns.Client{
			Net:     upstream.Protocol,
			Timeout: time.Duration(upstream.Timeout) * time.Millisecond,
		}
		m := new(dns.Msg)
		m.SetQuestion("dns.msftncsi.com.", dns.TypeA)
		var resp *dns.Msg
		resp, _, err = client.Exchange(m, address)
		if err == nil {
			if len(resp.Answer) == 0 {
				err = errors.New("empty response")
			} else {
				a, ok := resp.Answer[0].(*dns.A)
				if !ok {
					err = errors.New("bad response")
				} else if a.A.String() != "131.107.255.255" {
					err = errors.New("incorrect response")
				}
			}
		}
		printResult(msg, err)
	}
	checkRedis(&config.Handler.Redis)
	if config.Handler.GeoIp.Enable {
		fmt.Println("checking geoip...")
		var countryRecord struct {
			Location struct {
				Latitude        float64 `maxminddb:"latitude"`
				LongitudeOffset uintptr `maxminddb:"longitude"`
			} `maxminddb:"location"`
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		var asnRecord struct {
			AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
		}
		records := []interface{}{countryRecord, asnRecord}
		for i, dbFile := range []string{config.Handler.GeoIp.CountryDB, config.Handler.GeoIp.ASNDB} {
			msg = fmt.Sprintf("checking file stat : %s", dbFile)
			_, err = os.Stat(dbFile)
			printResult(msg, err)
			if err == nil {
				msg = fmt.Sprintf("checking db : %s", dbFile)
				var db *maxminddb.Reader
				db, err = maxminddb.Open(dbFile)
				printResult(msg, err)
				if err == nil {
					msg = fmt.Sprintf("checking db query results")
					err = db.Lookup(net.ParseIP("46.19.36.12"), &records[i])
					printResult(msg, err)
				}
			}
		}
	}
	if config.ErrorLog.Enable {
		checkLog(&config.ErrorLog)
	}
	if config.Handler.Log.Enable {
		checkLog(&config.Handler.Log)
	}
}

func main() {
	configPtr := flag.String("c", "config.json", "path to config file")
	verifyPtr := flag.Bool("t", false, "verify configuration")

	flag.Parse()

	configFile = *configPtr
	if *verifyPtr {
		Verify(configFile)
		return
	}

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
