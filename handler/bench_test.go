package handler

import (
	"arvancloud/redins/test"
	"github.com/hawell/logger"
	"github.com/miekg/dns"
	"log"
	"os"
	"testing"
)

var benchZone = "bench.zon."

var benchEntries = [][]string{
	{
		"www",
		`{
				"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]},
				"aaaa":{"ttl":300, "records":[{"ip":"::1"}]},
			}`,
	},
	{
		"www2",
		`{
				"cname":{"ttl":300, "host":"www.bench.zon."},
			}`,
	},
}

var benchTestHandler *DnsRequestHandler

func TestMain(m *testing.M) {
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)

	benchTestHandler = NewHandler(&defaultConfig)
	err := benchTestHandler.Redis.Del("*")
	log.Println(err)
	err = benchTestHandler.Redis.SAdd("redins:zones", benchZone)
	log.Println(err)
	err = benchTestHandler.Redis.Set("redins:zones:"+benchZone+":config", "{\"cname_flattening\": false}")
	log.Println(err)
	for _, cmd := range benchEntries {
		err := benchTestHandler.Redis.HSet("redins:zones:"+benchZone, cmd[0], cmd[1])
		if err != nil {
			log.Printf("[ERROR] cannot connect to redis: %s", err)
			return
		}
	}

	benchTestHandler.LoadZones()
	os.Exit(m.Run())
}

var response dns.Msg

func BenchmarkA(b *testing.B) {
	tc := test.Case{
		Qname: "www.bench.zon.", Qtype: dns.TypeA,
	}
	var resp *dns.Msg
	for n := 0; n < b.N; n++ {
		r := tc.Msg()
		w := test.NewRecorder(&test.ResponseWriter{})
		state := NewRequestContext(w, r)
		benchTestHandler.HandleRequest(state)

		resp = w.Msg
	}
	response = *resp
}

func BenchmarkAAAA(b *testing.B) {
	tc := test.Case{
		Qname: "www.bench.zon.", Qtype: dns.TypeAAAA,
	}
	var resp *dns.Msg
	for n := 0; n < b.N; n++ {
		r := tc.Msg()
		w := test.NewRecorder(&test.ResponseWriter{})
		state := NewRequestContext(w, r)
		benchTestHandler.HandleRequest(state)

		resp = w.Msg
	}
	response = *resp
}

func BenchmarkCNAME(b *testing.B) {
	tc := test.Case{
		Qname: "www2.bench.zon.", Qtype: dns.TypeA,
	}
	var resp *dns.Msg
	for n := 0; n < b.N; n++ {
		r := tc.Msg()
		w := test.NewRecorder(&test.ResponseWriter{})
		state := NewRequestContext(w, r)
		benchTestHandler.HandleRequest(state)

		resp = w.Msg
	}
	response = *resp
}

func BenchmarkNXDomain(b *testing.B) {
	tc := test.Case{
		Qname: "www3.bench.zon.", Qtype: dns.TypeA,
	}
	var resp *dns.Msg
	for n := 0; n < b.N; n++ {
		r := tc.Msg()
		w := test.NewRecorder(&test.ResponseWriter{})
		state := NewRequestContext(w, r)
		benchTestHandler.HandleRequest(state)

		resp = w.Msg
	}
	response = *resp
}

func BenchmarkNotAuth(b *testing.B) {
	tc := test.Case{
		Qname: "www.bench2.zon.", Qtype: dns.TypeA,
	}
	var resp *dns.Msg
	for n := 0; n < b.N; n++ {
		r := tc.Msg()
		w := test.NewRecorder(&test.ResponseWriter{})
		state := NewRequestContext(w, r)
		benchTestHandler.HandleRequest(state)

		resp = w.Msg
	}
	response = *resp
}
