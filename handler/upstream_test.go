package handler

import (
	"log"
	"sync"
	"testing"

	"arvancloud/redins/test"
	"github.com/coredns/coredns/request"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	"github.com/miekg/dns"
)

var upstreamTestConfig = HandlerConfig{
	MaxTtl:           300,
	CacheTimeout:     60,
	ZoneReload:       600,
	UpstreamFallback: true,
	Redis: uperdis.RedisConfig{
		Ip:             "redis",
		Port:           6379,
		DB:             0,
		Password:       "",
		Prefix:         "test_",
		Suffix:         "_test",
		Connection: uperdis.RedisConnectionConfig{
			MaxIdleConnections:   10,
			MaxActiveConnections: 10,
			ConnectTimeout:       500,
			ReadTimeout:          500,
			IdleKeepAlive:        30,
			MaxKeepAlive:         0,
			WaitForConnection:    true,
		},
	},
	Log: logger.LogConfig{
		Enable: false,
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
	},
}

func TestUpstream(t *testing.T) {
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)
	u := NewUpstream(upstreamTestConfig.Upstream)
	rs, res := u.Query("google.com.", dns.TypeAAAA)
	if len(rs) == 0 || res != 0 {
		log.Printf("[ERROR] AAAA failed")
		t.Fail()
	}
	rs, res = u.Query("google.com.", dns.TypeA)
	if len(rs) == 0 || res != 0 {
		log.Printf("[ERROR] A failed")
		t.Fail()
	}
	rs, res = u.Query("google.com.", dns.TypeTXT)
	if len(rs) == 0 || res != 0 {
		log.Printf("[ERROR] TXT failed")
		t.Fail()
	}
}

func TestFallback(t *testing.T) {
	tc := test.Case{
		Qname: "google.com.", Qtype: dns.TypeAAAA,
	}
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)

	h := NewHandler(&upstreamTestConfig)

	r := tc.Msg()
	w := test.NewRecorder(&test.ResponseWriter{})
	state := request.Request{W: w, Req: r}
	h.HandleRequest(&state)

	resp := w.Msg

	if resp.Rcode != dns.RcodeSuccess {
		t.Fail()
	}
}

func TestAsyncQuery(t *testing.T) {
	tcs := []test.Case{
		{
			Qname: "dns.msftncsi.com.", Qtype: dns.TypeA,
			Answer: []dns.RR{
				test.A("dns.msftncsi.com.	303	IN	A	131.107.255.255"),
			},
		},
		{
			Qname: "dns.msftncsi.com.", Qtype: dns.TypeAAAA,
			Answer: []dns.RR{
				test.AAAA("dns.msftncsi.com.	303	IN	AAAA	fd3e:4f5a:5b81::1"),
			},
		},
		{
			Qname: "dns.msftncsi.com.", Qtype: dns.TypeTXT,
		},
	}
	h := NewHandler(&upstreamTestConfig)
	wg := sync.WaitGroup{}
	wg.Add(len(tcs))
	for _, tc := range tcs {
		go func(tc test.Case) {

			r := tc.Msg()
			w := test.NewRecorder(&test.ResponseWriter{})
			state := request.Request{W: w, Req: r}
			h.HandleRequest(&state)

			resp := w.Msg
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Fail()
			}
			wg.Done()
		}(tc)
	}
	wg.Wait()
}