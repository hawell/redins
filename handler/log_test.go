package handler

import (
	"arvancloud/redins/handler/logformat"
	"arvancloud/redins/test"
	"bytes"
	"fmt"
	"github.com/coredns/coredns/request"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	jsoniter "github.com/json-iterator/go"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"
	"time"
	capnp "zombiezen.com/go/capnproto2"
)

var logTestConfig = HandlerConfig{
	MaxTtl:            300,
	CacheTimeout:      60,
	ZoneReload:        600,
	LogSourceLocation: true,
	Redis: uperdis.RedisConfig{
		Address:  "redis:6379",
		Net:      "tcp",
		DB:       0,
		Password: "",
		Prefix:   "test_",
		Suffix:   "_test",
	},
	Log: logger.LogConfig{
		Enable: true,
		Path:   "/tmp/test.log",
		Format: "json",
		Level:  "info",
		Target: "file",
		Kafka: logger.KafkaConfig{
			Enable:      false,
			Compression: "none",
			Brokers:     []string{"127.0.0.1:9093"},
			Topic:       "redins",
		},
	},
	Upstream: []UpstreamConfig{
		{
			Ip:       "1.1.1.1",
			Port:     53,
			Protocol: "udp",
			Timeout:  1000,
		},
	},
	GeoIp: GeoIpConfig{
		Enable:    true,
		CountryDB: "../geoCity.mmdb",
		ASNDB:     "../geoIsp.mmdb",
	},
}

var logZone = "zone.log."

var logZoneConfig = `{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.zone.log.","ns":"ns1.zone.log.","refresh":44,"retry":55,"expire":66},"domain_id":"d5cb15ec-cbfa-11e9-8ea5-9baaa1851180"}`

var logZoneEntries = [][]string{
	{"www",
		`{"a":{"ttl":300, "records":[{"ip":"127.0.0.1", "country":""}],"filter":{"count":"multi","order":"none","geo_filter":"none"}}}`,
	},
	{"www2",
		`{"a":{"ttl":300, "records":[{"ip":"127.0.0.1", "country":""}],"filter":{"count":"multi","order":"none","geo_filter":"none"}}}`,
	},
}

func TestJsonLog(t *testing.T) {
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)
	os.Remove("/tmp/test.log")

	logTestConfig.Log.Format = "json"
	h := NewHandler(&logTestConfig)
	h.Redis.Del("*")
	h.Redis.SAdd("redins:zones", logZone)
	for _, cmd := range logZoneEntries {
		err := h.Redis.HSet("redins:zones:"+logZone, cmd[0], cmd[1])
		if err != nil {
			log.Printf("[ERROR] cannot connect to redis: %s", err)
			t.Fail()
		}
	}
	h.Redis.Set("redins:zones:"+logZone+":config", logZoneConfig)
	h.LoadZones()
	tc := test.Case{
		Qname: "www.zone.log",
		Qtype: dns.TypeA,
	}
	r := tc.Msg()
	w := test.NewRecorder(&test.ResponseWriter{})
	state := request.Request{W: w, Req: r}
	h.HandleRequest(&state)
	time.Sleep(time.Millisecond * 100)
	b, _ := ioutil.ReadFile("/tmp/test.log")
	m1 := map[string]interface{}{
		"client_subnet": "",
		"domain_uuid":   "d5cb15ec-cbfa-11e9-8ea5-9baaa1851180",
		"level":         "info",
		"log_type":      "request",
		"msg":           "dns request",
		"record":        "www.zone.log.",
		"response_code": float64(0),
		"source_ip":     "10.240.0.1",
		"type":          "A",
	}
	m2 := make(map[string]interface{})
	jsoniter.Unmarshal(b, &m2)
	for key := range m1 {
		if m1[key] != m2[key] {
			fmt.Println(key)
			fmt.Printf("%v %T\n", m1[key], m1[key])
			fmt.Printf("%v %T\n", m2[key], m2[key])
			t.Fail()
		}
	}
}

func TestCapnpLog(t *testing.T) {
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)
	os.Remove("/tmp/test.log")

	logTestConfig.Log.Format = "capnp_request"
	h := NewHandler(&logTestConfig)
	h.Redis.Del("*")
	h.Redis.SAdd("redins:zones", logZone)
	for _, cmd := range logZoneEntries {
		err := h.Redis.HSet("redins:zones:"+logZone, cmd[0], cmd[1])
		if err != nil {
			log.Printf("[ERROR] cannot connect to redis: %s", err)
			t.Fail()
		}
	}
	h.Redis.Set("redins:zones:"+logZone+":config", logZoneConfig)
	h.LoadZones()
	tc := test.Case{
		Qname: "www2.zone.log",
		Qtype: dns.TypeA,
	}
	r := tc.Msg()
	w := test.NewRecorder(&test.ResponseWriter{})
	state := request.Request{W: w, Req: r}
	h.HandleRequest(&state)
	h.HandleRequest(&state)
	time.Sleep(time.Millisecond * 100)
	logFile, err := os.OpenFile("/tmp/test.log", os.O_RDONLY, 0666)
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	decoder := capnp.NewDecoder(logFile)

	for i := 0; i < 2; i++ {
		msg, err := decoder.Decode()
		if err != nil {
			fmt.Println(err)
			t.Fail()
		}
		requestLog, err := logformat.ReadRootRequestLog(msg)
		if err != nil {
			fmt.Println(err)
			t.Fail()
		}
		record, err := requestLog.Record()
		if err != nil {
			fmt.Println(err)
			t.Fail()
		}
		if record != "www2.zone.log." {
			t.Fail()
		}
	}
}

func TestCapnpLogNotAuth(t *testing.T) {
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)
	os.Remove("/tmp/test.log")

	logTestConfig.Log.Format = "capnp_request"
	h := NewHandler(&logTestConfig)
	h.Redis.Del("*")
	h.LoadZones()
	tc := test.Case{
		Qname: "www2.zone.log",
		Qtype: dns.TypeA,
	}
	r := tc.Msg()
	w := test.NewRecorder(&test.ResponseWriter{})
	state := request.Request{W: w, Req: r}
	h.HandleRequest(&state)
	time.Sleep(time.Millisecond * 100)
	logFile, err := os.OpenFile("/tmp/test.log", os.O_RDONLY, 0666)
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	decoder := capnp.NewDecoder(logFile)

	msg, err := decoder.Decode()
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	requestLog, err := logformat.ReadRootRequestLog(msg)
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	resp := requestLog.Responsecode()
	if resp != dns.RcodeNotAuth {
		t.Fail()
	}
}

func TestKafkaCapnpLog(t *testing.T) {
	t.Skip("skip kafka test")

	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)
	os.Remove("/tmp/test.log")

	logTestConfig.Log.Format = "text"
	logTestConfig.Log.Kafka.Enable = true
	logTestConfig.Log.Kafka.Format = "capnp_request"
	h := NewHandler(&logTestConfig)
	h.Redis.Del("*")
	h.Redis.SAdd("redins:zones", logZone)
	for _, cmd := range logZoneEntries {
		err := h.Redis.HSet("redins:zones:"+logZone, cmd[0], cmd[1])
		if err != nil {
			log.Printf("[ERROR] cannot connect to redis: %s", err)
			t.Fail()
		}
	}
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassANY, Rdlength: 0, Ttl: 300},
		Option: []dns.EDNS0{
			&dns.EDNS0_SUBNET{
				Address:       net.ParseIP("94.76.229.204"),
				Code:          dns.EDNS0SUBNET,
				Family:        1,
				SourceNetmask: 32,
				SourceScope:   0,
			},
		},
	}
	h.Redis.Set("redins:zones:"+logZone+":config", logZoneConfig)
	h.LoadZones()
	tc := test.Case{
		Qname: "www2.zone.log",
		Qtype: dns.TypeA,
	}
	r := tc.Msg()
	r.Extra = append(r.Extra, opt)
	w := test.NewRecorder(&test.ResponseWriter{})
	state := request.Request{W: w, Req: r}
	h.HandleRequest(&state)
	time.Sleep(time.Second)
}

func TestUdpCapnpLog(t *testing.T){
	go func() {
		pc, err := net.ListenPacket("udp", "localhost:9090")
		if err != nil {
			fmt.Println(err)
			t.Fail()
			return
		}
		for i := 0; i < 2; i++ {
			buffer := make([]byte, 1024)
			n, _, err := pc.ReadFrom(buffer)
			fmt.Println("n = ", n)
			if err != nil {
				fmt.Println(err)
				t.Fail()
				return
			}
			r := bytes.NewReader(buffer)
			decoder := capnp.NewDecoder(r)

			msg, err := decoder.Decode()
			if err != nil {
				fmt.Println(err)
				t.Fail()
			}
			requestLog, err := logformat.ReadRootRequestLog(msg)
			if err != nil {
				fmt.Println(err)
				t.Fail()
			}
			fmt.Println(requestLog)
			record, err := requestLog.Record()
			if err != nil {
				fmt.Println(err)
				t.Fail()
			}
			if record != "www2.zone.log." {
				t.Fail()
			}
		}
		pc.Close()
	}()

	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)
	os.Remove("/tmp/test.log")

	logTestConfig.Log.Format = "capnp_request"
	logTestConfig.Log.Target = "udp"
	logTestConfig.Log.Path = "localhost:9090"
	h := NewHandler(&logTestConfig)
	h.Redis.Del("*")
	h.Redis.SAdd("redins:zones", logZone)
	for _, cmd := range logZoneEntries {
		err := h.Redis.HSet("redins:zones:"+logZone, cmd[0], cmd[1])
		if err != nil {
			log.Printf("[ERROR] cannot connect to redis: %s", err)
			t.Fail()
		}
	}
	h.Redis.Set("redins:zones:"+logZone+":config", logZoneConfig)
	h.LoadZones()
	tc := test.Case{
		Qname: "www2.zone.log",
		Qtype: dns.TypeA,
	}
	r := tc.Msg()
	w := test.NewRecorder(&test.ResponseWriter{})
	state := request.Request{W: w, Req: r}
	h.HandleRequest(&state)
	h.HandleRequest(&state)
	time.Sleep(time.Millisecond * 100)
}