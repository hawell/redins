package handler

import (
	"arvancloud/redins/test"
	"errors"
	"fmt"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	"github.com/miekg/dns"
	"net"
	"strings"
	"testing"
	"time"
)

type TestCase struct {
	Name           string
	Description    string
	Enabled        bool
	Config         HandlerConfig
	Initialize     func(testCase *TestCase) (*DnsRequestHandler, error)
	ApplyAndVerify func(testCase *TestCase, handler *DnsRequestHandler, t *testing.T)
	Zones          []string
	ZoneConfigs    []string
	Entries        [][][]string
	TestCases      []test.Case
}

func defaultInitialize(testCase *TestCase) (*DnsRequestHandler, error) {
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)

	h := NewHandler(&testCase.Config)
	if err := h.Redis.Del("*"); err != nil {
		return nil, err
	}
	for i, zone := range testCase.Zones {
		if err := h.Redis.SAdd("redins:zones", zone); err != nil {
			return nil, err
		}
		for _, cmd := range testCase.Entries[i] {
			err := h.Redis.HSet("redins:zones:"+zone, cmd[0], cmd[1])
			if err != nil {
				return nil, errors.New(fmt.Sprintf("[ERROR] cannot connect to redis: %s", err))
			}
		}
		if err := h.Redis.Set("redins:zones:"+zone+":config", testCase.ZoneConfigs[i]); err != nil {
			return nil, err
		}
	}
	h.LoadZones()
	return h, nil
}

func defaultApplyAndVerify(testCase *TestCase, handler *DnsRequestHandler, t *testing.T) {
	for i, tc := range testCase.TestCases {

		r := tc.Msg()
		w := test.NewRecorder(&test.ResponseWriter{})
		state := NewRequestContext(w, r)
		handler.HandleRequest(state)

		resp := w.Msg

		if err := test.SortAndCheck(resp, tc); err != nil {
			fmt.Println(i, err, tc.Qname, tc.Answer, resp.Answer)
			t.Fail()
		}
	}
}

var defaultConfig = HandlerConfig{
	MaxTtl:       300,
	CacheTimeout: 60,
	ZoneReload:   600,
	Redis: uperdis.RedisConfig{
		Address:  "redis:6379",
		Net:      "tcp",
		DB:       0,
		Password: "",
		Prefix:   "test_",
		Suffix:   "_test",
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
		ASNDB:     "../geoIsp.mmdb",
	},
}

var testCases = []*TestCase{
	{
		Name:           "Basic Usage",
		Description:    "Test Basic functionality",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"example.com."},
		ZoneConfigs:    []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.example.com.","ns":"ns1.example.com.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"@",
					`{"ns":{"ttl":300, "records":[{"host":"ns1.example.com."},{"host":"ns2.example.com."}]}}`,
				},
				{"x",
					`{
            			"a":{"ttl":300, "records":[{"ip":"1.2.3.4", "country":"ES"},{"ip":"5.6.7.8", "country":""}]},
            			"aaaa":{"ttl":300, "records":[{"ip":"::1"}]},
            			"txt":{"ttl":300, "records":[{"text":"foo"},{"text":"bar"}]},
            			"mx":{"ttl":300, "records":[{"host":"mx1.example.com.", "preference":10},{"host":"mx2.example.com.", "preference":10}]},
            			"srv":{"ttl":300, "records":[{"target":"sip.example.com.","port":555,"priority":10,"weight":100}]}
            		}`,
				},
				{"y",
					`{"cname":{"ttl":300, "host":"x.example.com."}}`,
				},
				{"ns1",
					`{"a":{"ttl":300, "records":[{"ip":"2.2.2.2"}]}}`,
				},
				{"ns2",
					`{"a":{"ttl":300, "records":[{"ip":"3.3.3.3"}]}}`,
				},
				{"_sip._tcp",
					`{"srv":{"ttl":300, "records":[{"target":"sip.example.com.","port":555,"priority":10,"weight":100}]}}`,
				},
				{"_443._tcp.www",
					`{"tlsa":{"ttl":300, "records":[{"usage":0, "selector":0, "matching_type":1, "certificate":"d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"}]}}`,
				},
				{"_990._tcp",
					`{
            			"tlsa":{"ttl":300, "records":[
                			{"usage":1, "selector":1, "matching_type":1, "certificate":"1CFC98A706BCF3683015"},
                			{"usage":1, "selector":1, "matching_type":1, "certificate":"62D5414CD1CC657E3D30"}
						]}
					}`,
				},
				{"sip",
					`{
						"a":{"ttl":300, "records":[{"ip":"7.7.7.7"}]},
            			"aaaa":{"ttl":300, "records":[{"ip":"::1"}]}
					}`,
				},
				{"t.u.v.w",
					`{"a":{"ttl":300, "records":[{"ip":"9.9.9.9"}]}}`,
				},
				{"cnametonx",
					`{"cname":{"ttl":300, "host":"notexists.example.com."}}`,
				},
			},
		},
		TestCases: []test.Case{
			// NOAUTH Test
			{
				Qname: "dsdsd.sdf.dfd.", Qtype: dns.TypeA,
				Rcode: dns.RcodeNotAuth,
			},
			// A Test
			{
				Qname: "x.example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("x.example.com. 300 IN A 1.2.3.4"),
					test.A("x.example.com. 300 IN A 5.6.7.8"),
				},
			},
			// AAAA Test
			{
				Qname: "x.example.com.", Qtype: dns.TypeAAAA,
				Answer: []dns.RR{
					test.AAAA("x.example.com. 300 IN AAAA ::1"),
				},
			},
			// TXT Test
			{
				Qname: "x.example.com.", Qtype: dns.TypeTXT,
				Answer: []dns.RR{
					test.TXT("x.example.com. 300 IN TXT bar"),
					test.TXT("x.example.com. 300 IN TXT foo"),
				},
			},
			// CNAME Test
			{
				Qname: "y.example.com.", Qtype: dns.TypeCNAME,
				Answer: []dns.RR{
					test.CNAME("y.example.com. 300 IN CNAME x.example.com."),
				},
			},
			// NS Test
			{
				Qname: "example.com.", Qtype: dns.TypeNS,
				Answer: []dns.RR{
					test.NS("example.com. 300 IN NS ns1.example.com."),
					test.NS("example.com. 300 IN NS ns2.example.com."),
				},
			},
			// MX Test
			{
				Qname: "x.example.com.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("x.example.com. 300 IN MX 10 mx1.example.com."),
					test.MX("x.example.com. 300 IN MX 10 mx2.example.com."),
				},
			},
			// SRV Test
			{
				Qname: "_sip._tcp.example.com.", Qtype: dns.TypeSRV,
				Answer: []dns.RR{
					test.SRV("_sip._tcp.example.com. 300 IN SRV 10 100 555 sip.example.com."),
				},
			},
			// TLSA Test
			{
				Qname: "_443._tcp.www.example.com.", Qtype: dns.TypeTLSA,
				Answer: []dns.RR{
					test.TLSA("_443._tcp.www.example.com. 300 IN TLSA 0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"),
				},
			},
			{
				Qname: "_990._tcp.example.com.", Qtype: dns.TypeTLSA,
				Answer: []dns.RR{
					test.TLSA("_990._tcp.example.com. 300 IN TLSA 1 1 1 1CFC98A706BCF3683015"),
					test.TLSA("_990._tcp.example.com. 300 IN TLSA 1 1 1 62D5414CD1CC657E3D30"),
				},
			},
			// NXDOMAIN Test
			{
				Qname: "notexists.example.com.", Qtype: dns.TypeA,
				Rcode: dns.RcodeNameError,
				Ns: []dns.RR{
					test.SOA("example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1460498836 44 55 66 100"),
				},
			},
			// NXDOMAIN through CNAME Test
			{
				Qname: "cnametonx.example.com.", Qtype: dns.TypeA,
				Rcode: dns.RcodeNameError,
				Answer: []dns.RR{
					test.CNAME("cnametonx.example.com. 300 IN CNAME notexists.example.com."),
				},
				Ns: []dns.RR{
					test.SOA("example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1460498836 44 55 66 100"),
				},
			},
			// SOA Test
			{
				Qname: "example.com.", Qtype: dns.TypeSOA,
				Answer: []dns.RR{
					test.SOA("example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1460498836 44 55 66 100"),
				},
			},
			// not implemented
			{
				Qname: "example.com.", Qtype: dns.TypeUNSPEC,
				Rcode: dns.RcodeNotImplemented,
				Ns: []dns.RR{
					test.SOA("example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 1460498836 44 55 66 100"),
				},
			},
			// Empty non-terminal Test
			// FIXME: should return NOERROR instead of NXDOMAIN
			/*
			   {
			       Qname:"v.w.example.com.", Qtype: dns.TypeA,
			   },
			*/
		},
	},
	{
		Name:           "WildCard",
		Description:    "tests related to handling of different wildcard scenarios",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"example.net."},
		ZoneConfigs:    []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.example.net.","ns":"ns1.example.net.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"@",
					`{"ns":{"ttl":300, "records":[{"host":"ns1.example.net."},{"host":"ns2.example.net."}]}}`,
				},
				{"sub.*",
					`{"txt":{"ttl":300, "records":[{"text":"this is not a wildcard"}]}}`,
				},
				{"host1",
					`{"a":{"ttl":300, "records":[{"ip":"5.5.5.5"}]}}`,
				},
				{"subdel",
					`{"ns":{"ttl":300, "records":[{"host":"ns1.subdel.example.net."},{"host":"ns2.subdel.example.net."}]}}`,
				},
				{"*",
					`{
						"txt":{"ttl":300, "records":[{"text":"this is a wildcard"}]},
            			"mx":{"ttl":300, "records":[{"host":"host1.example.net.","preference": 10}]}
					}`,
				},
				{"_ssh._tcp.host1",
					`{"srv":{"ttl":300, "records":[{"target":"tcp.example.com.","port":123,"priority":10,"weight":100}]}}`,
				},
				{"_ssh._tcp.host2",
					`{"srv":{"ttl":300, "records":[{"target":"tcp.example.com.","port":123,"priority":10,"weight":100}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "host3.example.net.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("host3.example.net. 300 IN MX 10 host1.example.net."),
				},
			},
			{
				Qname: "host3.example.net.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.net. 300 IN SOA ns1.example.net. hostmaster.example.net. 1460498836 44 55 66 100"),
				},
			},
			{
				Qname: "foo.bar.example.net.", Qtype: dns.TypeTXT,
				Answer: []dns.RR{
					test.TXT("foo.bar.example.net. 300 IN TXT \"this is a wildcard\""),
				},
			},
			{
				Qname: "host1.example.net.", Qtype: dns.TypeMX,
				Ns: []dns.RR{
					test.SOA("example.net. 300 IN SOA ns1.example.net. hostmaster.example.net. 1460498836 44 55 66 100"),
				},
			},
			{
				Qname: "sub.*.example.net.", Qtype: dns.TypeMX,
				Ns: []dns.RR{
					test.SOA("example.net. 300 IN SOA ns1.example.net. hostmaster.example.net. 1460498836 44 55 66 100"),
				},
			},
			{
				Qname: "host.subdel.example.net.", Qtype: dns.TypeA,
				Rcode: dns.RcodeNameError,
				Ns: []dns.RR{
					test.SOA("example.net. 300 IN SOA ns1.example.net. hostmaster.example.net. 1460498836 44 55 66 100"),
				},
			},
			{
				Qname: "ghost.*.example.net.", Qtype: dns.TypeMX,
				Rcode: dns.RcodeNameError,
				Ns: []dns.RR{
					test.SOA("example.net. 300 IN SOA ns1.example.net. hostmaster.example.net. 1460498836 44 55 66 100"),
				},
			},
			{
				Qname: "f.h.g.f.t.r.e.example.net.", Qtype: dns.TypeTXT,
				Answer: []dns.RR{
					test.TXT("f.h.g.f.t.r.e.example.net. 300 IN TXT \"this is a wildcard\""),
				},
			},
		},
	},
	{
		Name:           "CNAME",
		Description:    "normal cname functionality",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"example.aaa."},
		ZoneConfigs:    []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.example.aaa.","ns":"ns1.example.aaa.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"@",
					`{"ns":{"ttl":300, "records":[{"host":"ns1.example.aaa."},{"ttl":300, "host":"ns2.example.aaa."}]},}`,
				},
				{"x",
					`{
						"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]},
                		"aaaa":{"ttl":300, "records":[{"ip":"::1"}]},
                		"txt":{"ttl":300, "records":[{"text":"foo"},{"text":"bar"}]},
                		"mx":{"ttl":300, "records":[{"host":"mx1.example.aaa.", "preference":10},{"host":"mx2.example.aaa.", "preference":10}]},
                		"srv":{"ttl":300, "records":[{"target":"sip.example.aaa.","port":555,"priority":10,"weight":100}]}
					}`,
				},
				{"y",
					`{"cname":{"ttl":300, "host":"x.example.aaa."}}`,
				},
				{"z",
					`{"cname":{"ttl":300, "host":"y.example.aaa."}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "y.example.aaa.", Qtype: dns.TypeCNAME,
				Answer: []dns.RR{
					test.CNAME("y.example.aaa. 300 IN CNAME x.example.aaa."),
				},
			},
			{
				Qname: "z.example.aaa.", Qtype: dns.TypeCNAME,
				Answer: []dns.RR{
					test.CNAME("z.example.aaa. 300 IN CNAME y.example.aaa."),
				},
			},
			{
				Qname: "z.example.aaa.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("x.example.aaa. 300 IN A 1.2.3.4"),
					test.CNAME("y.example.aaa. 300 IN CNAME x.example.aaa."),
					test.CNAME("z.example.aaa. 300 IN CNAME y.example.aaa."),
				},
			},
		},
	},
	{
		Name:           "empty values",
		Description:    "test handler behaviour with empty records",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"example.bbb."},
		ZoneConfigs:    []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.example.bbb.","ns":"ns1.example.bbb.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"x",
					`{}`,
				},
				{"y",
					`{"cname":{"ttl":300, "host":"x.example.bbb."}}`,
				},
				{"z",
					`{}`,
				},
			},
		},
		TestCases: []test.Case{
			// empty A test
			{
				Qname: "z.example.bbb.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty AAAA test
			{
				Qname: "z.example.bbb.", Qtype: dns.TypeAAAA,
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty TXT test
			{
				Qname: "z.example.bbb.", Qtype: dns.TypeTXT,
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty NS test
			{
				Qname: "z.example.bbb.", Qtype: dns.TypeNS,
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty MX test
			{
				Qname: "z.example.bbb.", Qtype: dns.TypeMX,
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty SRV test
			{
				Qname: "z.example.bbb.", Qtype: dns.TypeSRV,
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty CNAME test
			{
				Qname: "x.example.bbb.", Qtype: dns.TypeCNAME,
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty A test with cname
			{
				Qname: "y.example.bbb.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("y.example.bbb.	300	IN	CNAME	x.example.bbb."),
				},
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty AAAA test with cname
			{
				Qname: "y.example.bbb.", Qtype: dns.TypeAAAA,
				Answer: []dns.RR{
					test.CNAME("y.example.bbb.	300	IN	CNAME	x.example.bbb."),
				},
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty TXT test with cname
			{
				Qname: "y.example.bbb.", Qtype: dns.TypeTXT,
				Answer: []dns.RR{
					test.CNAME("y.example.bbb.	300	IN	CNAME	x.example.bbb."),
				},
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty NS test with cname
			{
				Qname: "y.example.bbb.", Qtype: dns.TypeNS,
				Answer: []dns.RR{
					test.CNAME("y.example.bbb.	300	IN	CNAME	x.example.bbb."),
				},
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty MX test with cname
			{
				Qname: "y.example.bbb.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.CNAME("y.example.bbb.	300	IN	CNAME	x.example.bbb."),
				},
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
			// empty SRV test with cname
			{
				Qname: "y.example.bbb.", Qtype: dns.TypeSRV,
				Answer: []dns.RR{
					test.CNAME("y.example.bbb.	300	IN	CNAME	x.example.bbb."),
				},
				Ns: []dns.RR{
					test.SOA("example.bbb. 300 IN SOA ns1.example.bbb. hostmaster.example.bbb. 1460498836 44 55 66 100"),
				},
			},
		},
	},
	{
		Name:           "long text",
		Description:    "text field longer than 255 bytes",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"example.ccc."},
		ZoneConfigs:    []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.example.ccc.","ns":"ns1.example.ccc.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"x",
					`{"txt":{"ttl":300, "records":[{"text":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "x.example.ccc.", Qtype: dns.TypeTXT,
				Answer: []dns.RR{
					test.TXT("x.example.ccc. 300 IN TXT \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""),
				},
			},
		},
	},
	{
		Name:           "cname flattening",
		Description:    "eliminate intermediate cname records when cname flatenning is enabled",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"example.ddd."},
		ZoneConfigs:    []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.example.ddd.","ns":"ns1.example.ddd.","refresh":44,"retry":55,"expire":66},"cname_flattening":true}`},
		Entries: [][][]string{
			{
				{"@",
					`{"ns":{"ttl":300, "records":[{"host":"ns1.example.ddd."},{"ttl":300, "host":"ns2.example.ddd."}]}}`,
				},
				{"a",
					`{
						"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]},
                		"aaaa":{"ttl":300, "records":[{"ip":"::1"}]},
                		"txt":{"ttl":300, "records":[{"text":"foo"},{"text":"bar"}]},
                		"mx":{"ttl":300, "records":[{"host":"mx1.example.ddd.", "preference":10},{"host":"mx2.example.ddd.", "preference":10}]},
                		"srv":{"ttl":300, "records":[{"target":"sip.example.ddd.","port":555,"priority":10,"weight":100}]}
					}`,
				},
				{"b",
					`{"cname":{"ttl":300, "host":"a.example.ddd."}}`,
				},
				{"c",
					`{"cname":{"ttl":300, "host":"b.example.ddd."}}`,
				},
				{"d",
					`{"cname":{"ttl":300, "host":"c.example.ddd."}}`,
				},
				{"e",
					`{"cname":{"ttl":300, "host":"d.example.ddd."}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "e.example.ddd.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("e.example.ddd. 300 IN A 1.2.3.4"),
				},
			},
			{
				Qname: "e.example.ddd.", Qtype: dns.TypeAAAA,
				Answer: []dns.RR{
					test.AAAA("e.example.ddd. 300 IN AAAA ::1"),
				},
			},
			{
				Qname: "e.example.ddd.", Qtype: dns.TypeTXT,
				Answer: []dns.RR{
					test.TXT("e.example.ddd. 300 IN TXT \"bar\""),
					test.TXT("e.example.ddd. 300 IN TXT \"foo\""),
				},
			},
			// MX Test
			{
				Qname: "e.example.ddd.", Qtype: dns.TypeMX,
				Answer: []dns.RR{
					test.MX("e.example.ddd. 300 IN MX 10 mx1.example.ddd."),
					test.MX("e.example.ddd. 300 IN MX 10 mx2.example.ddd."),
				},
			},
			// SRV Test
			{
				Qname: "e.example.ddd.", Qtype: dns.TypeSRV,
				Answer: []dns.RR{
					test.SRV("e.example.ddd. 300 IN SRV 10 100 555 sip.example.ddd."),
				},
			},
			{
				Qname: "e.example.ddd.", Qtype: dns.TypeCNAME,
				Answer: []dns.RR{
					test.CNAME("e.example.ddd. 300 IN CNAME d.example.ddd."),
				},
			},
		},
	},
	{
		Name:           "caa test",
		Description:    "basic caa functionality",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"example.caa.", "nocaa.caa."},
		ZoneConfigs: []string{
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.example.caa.","ns":"ns1.example.caa.","refresh":44,"retry":55,"expire":66}}`,
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.nocaa.caa.","ns":"ns1.nocaa.caa.","refresh":44,"retry":55,"expire":66}}`,
		},
		Entries: [][][]string{
			{
				{"@",
					`{"caa":{"ttl":300, "records":[{"tag":"issue", "value":"godaddy.com;", "flag":0}]}}`,
				},
				{"a.b.c.d",
					`{"cname":{"ttl":300, "host":"b.c.d.example.caa."}}`,
				},
				{"b.c.d",
					`{"cname":{"ttl":300, "host":"c.d.example.caa."}}`,
				},
				{"c.d",
					`{"cname":{"ttl":300, "host":"d.example.caa."}}`,
				},
				{"d",
					`{"cname":{"ttl":300, "host":"example.caa."}}`,
				},
				{"x.y.z",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
				{"y.z",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
				{"z",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
				{"h",
					`{"caa":{"ttl":300, "records":[{"tag":"issue", "value":"godaddy2.com;", "flag":0}]}}`,
				},
				{"g.h",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
				{"j.g.h",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
			},
			{
				{"@",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
				{"www",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
				{"www2",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
				{"www3",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "example.caa.", Qtype: dns.TypeCAA,
				Answer: []dns.RR{
					test.CAA("example.caa.	300	IN	CAA	0 issue \"godaddy.com;\""),
				},
			},
			{
				Qname: "a.b.c.d.example.caa.", Qtype: dns.TypeCAA,
				Answer: []dns.RR{
					test.CNAME("a.b.c.d.example.caa. 300 IN CNAME b.c.d.example.caa."),
					test.CNAME("b.c.d.example.caa. 300 IN CNAME c.d.example.caa."),
					test.CNAME("c.d.example.caa. 300 IN CNAME d.example.caa."),
					test.CNAME("d.example.caa. 300 IN CNAME example.caa."),
					test.CAA("example.caa. 300 IN CAA 0 issue \"godaddy.com;\""),
				},
			},
			{
				Qname: "x.y.z.example.caa.", Qtype: dns.TypeCAA,
				Answer: []dns.RR{
					test.CAA("x.y.z.example.caa.	300	IN	CAA	0 issue \"godaddy.com;\""),
				},
			},
			{
				Qname: "h.example.caa.", Qtype: dns.TypeCAA,
				Answer: []dns.RR{
					test.CAA("h.example.caa.	300	IN	CAA	0 issue \"godaddy2.com;\""),
				},
			},
			{
				Qname: "g.h.example.caa.", Qtype: dns.TypeCAA,
				Answer: []dns.RR{
					test.CAA("g.h.example.caa.	300	IN	CAA	0 issue \"godaddy2.com;\""),
				},
			},
			{
				Qname: "j.g.h.example.caa.", Qtype: dns.TypeCAA,
				Answer: []dns.RR{
					test.CAA("j.g.h.example.caa.	300	IN	CAA	0 issue \"godaddy2.com;\""),
				},
			},
			{
				Qname: "nocaa.caa.", Qtype: dns.TypeCAA,
				Ns: []dns.RR{
					test.SOA("nocaa.caa.	300	IN	SOA	ns1.nocaa.caa. hostmaster.nocaa.caa. 1570970363 44 55 66 100"),
				},
			},
			{
				Qname: "www.nocaa.caa.", Qtype: dns.TypeCAA,
				Ns: []dns.RR{
					test.SOA("nocaa.caa.	300	IN	SOA	ns1.nocaa.caa. hostmaster.nocaa.caa. 1570970363 44 55 66 100"),
				},
			},
			{
				Qname: "www2.nocaa.caa.", Qtype: dns.TypeCAA,
				Ns: []dns.RR{
					test.SOA("nocaa.caa.	300	IN	SOA	ns1.nocaa.caa. hostmaster.nocaa.caa. 1570970363 44 55 66 100"),
				},
			},
			{
				Qname: "www3.nocaa.caa.", Qtype: dns.TypeCAA,
				Ns: []dns.RR{
					test.SOA("nocaa.caa.	300	IN	SOA	ns1.nocaa.caa. hostmaster.nocaa.caa. 1570970363 44 55 66 100"),
				},
			},
		},
	},
	{
		Name:           "PTR test",
		Description:    "basic ptr functionality",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"0.0.127.in-addr.arpa.", "20.127.10.in-addr.arpa."},
		ZoneConfigs:    []string{"", ""},
		Entries: [][][]string{
			{
				{"1",
					`{"ptr":{"ttl":300, "domain":"localhost"}}`,
				},
			},
			{
				{"54",
					`{"ptr":{"ttl":300, "domain":"example.fff"}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "1.0.0.127.in-addr.arpa.", Qtype: dns.TypePTR,
				Answer: []dns.RR{
					test.PTR("1.0.0.127.in-addr.arpa. 300 IN PTR localhost."),
				},
			},
			{
				Qname: "54.20.127.10.in-addr.arpa.", Qtype: dns.TypePTR,
				Answer: []dns.RR{
					test.PTR("54.20.127.10.in-addr.arpa. 300 IN PTR example.fff."),
				},
			},
		},
	},
	{
		Name:           "ANAME test",
		Description:    "test aname functionality",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"arvancloud.com.", "arvan.an."},
		ZoneConfigs: []string{
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.arvancloud.com.","ns":"ns1.arvancloud.com.","refresh":44,"retry":55,"expire":66}}`,
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.arvan.an.","ns":"ns1.arvan.an.","refresh":44,"retry":55,"expire":66}}`,
		},
		Entries: [][][]string{
			{
				{"@",
					`{"aname":{"location":"aname.arvan.an."}}`,
				},
				{"nxlocal",
					`{"aname":{"location":"nx.arvancloud.com."}}`,
				},
				{"empty",
					`{"aname":{"location":"e.arvancloud.com."}}`,
				},
				{"e",
					`"txt":{"ttl":300, "records":[{"text":"foo"}]},`,
				},
				{"upstream",
					`{"aname":{"location":"dns.msftncsi.com."}}`,
				},
				{"nxupstream",
					`{"aname":{"location":"anamex.arvan.an."}}`,
				},
			},
			{
				{"aname",
					`{"a":{"ttl":300, "records":[{"ip":"6.5.6.5"}]}, "aaaa":{"ttl":300, "records":[{"ip":"::1"}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "arvancloud.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("arvancloud.com. 300 IN A 6.5.6.5"),
				},
			},
			{
				Qname: "arvancloud.com.", Qtype: dns.TypeAAAA,
				Answer: []dns.RR{
					test.AAAA("arvancloud.com. 300 IN AAAA ::1"),
				},
			},
			{
				Qname: "upstream.arvancloud.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("upstream.arvancloud.com. 303 IN A 131.107.255.255"),
				},
			},
			{
				Qname: "upstream.arvancloud.com.", Qtype: dns.TypeAAAA,
				Answer: []dns.RR{
					test.AAAA("upstream.arvancloud.com. 303 IN AAAA fd3e:4f5a:5b81::1"),
				},
			},
			{
				Qname: "nxlocal.arvancloud.com.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("arvancloud.com.	300	IN	SOA	ns1.arvancloud.com. hostmaster.arvancloud.com. 1570970363 44 55 66 100"),
				},
				Rcode: dns.RcodeNameError,
			},
			{
				Qname: "nxlocal.arvancloud.com.", Qtype: dns.TypeAAAA,
				Ns: []dns.RR{
					test.SOA("arvancloud.com.	300	IN	SOA	ns1.arvancloud.com. hostmaster.arvancloud.com. 1570970363 44 55 66 100"),
				},
				Rcode: dns.RcodeNameError,
			},
			{
				Qname: "empty.arvancloud.com.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("arvancloud.com.	300	IN	SOA	ns1.arvancloud.com. hostmaster.arvancloud.com. 1570970363 44 55 66 100"),
				},
			},
			{
				Qname: "empty.arvancloud.com.", Qtype: dns.TypeAAAA,
				Ns: []dns.RR{
					test.SOA("arvancloud.com.	300	IN	SOA	ns1.arvancloud.com. hostmaster.arvancloud.com. 1570970363 44 55 66 100"),
				},
			},
			{
				Qname: "nxupstream.arvancloud.com.", Qtype: dns.TypeA,
				Ns: []dns.RR{
					test.SOA("arvancloud.com.	300	IN	SOA	ns1.arvancloud.com. hostmaster.arvancloud.com. 1570970363 44 55 66 100"),
				},
				Rcode: dns.RcodeNameError,
			},
			{
				Qname: "nxupstream.arvancloud.com.", Qtype: dns.TypeAAAA,
				Ns: []dns.RR{
					test.SOA("arvancloud.com.	300	IN	SOA	ns1.arvancloud.com. hostmaster.arvancloud.com. 1570970363 44 55 66 100"),
				},
				Rcode: dns.RcodeNameError,
			},
		},
	},
	{
		Name:        "weighted aname test",
		Description: "weight filter should be applied on aname results as well",
		Enabled:     true,
		Config:      defaultConfig,
		Initialize:  defaultInitialize,
		ApplyAndVerify: func(testCase *TestCase, handler *DnsRequestHandler, t *testing.T) {
			ipsCount := []int{0, 0, 0}
			for i := 0; i < 1000; i++ {
				r := testCase.TestCases[0].Msg()
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg
				if resp.Rcode != dns.RcodeSuccess {
					fmt.Println("RcodeSuccess expected ", dns.RcodeToString[resp.Rcode], " received")
					t.Fail()
				}
				if len(resp.Answer) == 0 {
					fmt.Println("empty answer")
					t.Fail()
				}
				a := resp.Answer[0].(*dns.A)
				switch a.A.String() {
				case "1.1.1.1":
					ipsCount[0]++
				case "2.2.2.2":
					ipsCount[1]++
				case "3.3.3.3":
					ipsCount[2]++
				default:
					fmt.Println("invalid ip : ", a.A.String())
					t.Fail()
				}
			}
			if !(ipsCount[0] < ipsCount[1] && ipsCount[1] < ipsCount[2]) {
				fmt.Println("bad ip weight balance")
				t.Fail()
			}
			ipsCount = []int{0, 0, 0}
			for i := 0; i < 1000; i++ {
				r := testCase.TestCases[1].Msg()
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg
				if resp.Rcode != dns.RcodeSuccess {
					fmt.Println("RcodeSuccess expected ", dns.RcodeToString[resp.Rcode], " received")
					t.Fail()
				}
				if len(resp.Answer) == 0 {
					fmt.Println("empty answer")
					t.Fail()
				}
				aaaa := resp.Answer[0].(*dns.AAAA)
				switch aaaa.AAAA.String() {
				case "2001:db8::1":
					ipsCount[0]++
				case "2001:db8::2":
					ipsCount[1]++
				case "2001:db8::3":
					ipsCount[2]++
				default:
					fmt.Println("invalid ip : ", aaaa.AAAA.String())
					t.Fail()
				}
			}
			if !(ipsCount[0] < ipsCount[1] && ipsCount[1] < ipsCount[2]) {
				fmt.Println("bad ip weight balance")
				t.Fail()
			}
		},
		Zones: []string{"arvancloud.com.", "arvan.an."},
		ZoneConfigs: []string{
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.arvancloud.com.","ns":"ns1.arvancloud.com.","refresh":44,"retry":55,"expire":66}}`,
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.arvan.an.","ns":"ns1.arvan.an.","refresh":44,"retry":55,"expire":66}}`,
		},
		Entries: [][][]string{
			{
				{"upstream2",
					`{"aname":{"location":"aname2.arvan.an."}}`,
				},
			},
			{
				{"aname2",
					`{
						"a":{"ttl":300, "filter": {"count":"single", "order": "weighted", "geo_filter":"none"}, "records":[{"ip":"1.1.1.1", "weight":1},{"ip":"2.2.2.2", "weight":5},{"ip":"3.3.3.3", "weight":10}]},
						"aaaa":{"ttl":300, "filter": {"count":"single", "order": "weighted", "geo_filter":"none"}, "records":[{"ip":"2001:db8::1", "weight":1},{"ip":"2001:db8::2", "weight":5},{"ip":"2001:db8::3", "weight":10}]}
					}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "upstream2.arvancloud.com.", Qtype: dns.TypeA,
			},
			{
				Qname: "upstream2.arvancloud.com.", Qtype: dns.TypeAAAA,
			},
		},
	},
	{
		Name:        "geofilter test",
		Description: "test various geofilter scenarios",
		Enabled:     true,
		Config:      defaultConfig,
		Initialize:  defaultInitialize,
		ApplyAndVerify: func(testCase *TestCase, handler *DnsRequestHandler, t *testing.T) {
			var filterGeoSourceIps = []string{
				"127.0.0.1",
				"127.0.0.1",
				"127.0.0.1",
				"127.0.0.1",
				"127.0.0.1",
				"94.76.229.204",  // country = GB
				"154.11.253.242", // location = CA near US
				"212.83.32.45",   // ASN = 47447
				"212.83.32.45",   // country = DE, ASN = 47447
				"212.83.32.45",
				"178.18.89.144",
				"127.0.0.1",
				"213.95.10.76",   // DE
				"94.76.229.204",  // GB
				"154.11.253.242", // CA
				"127.0.0.1",
			}
			for i, tc := range testCase.TestCases {
				sa := filterGeoSourceIps[i]
				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassANY, Rdlength: 0, Ttl: 300},
					Option: []dns.EDNS0{
						&dns.EDNS0_SUBNET{
							Address:       net.ParseIP(sa),
							Code:          dns.EDNS0SUBNET,
							Family:        1,
							SourceNetmask: 32,
							SourceScope:   0,
						},
					},
				}
				r := tc.Msg()
				r.Extra = append(r.Extra, opt)
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg
				resp.Extra = nil

				if err := test.SortAndCheck(resp, tc); err != nil {
					fmt.Println(err)
					t.Fail()
				}
			}
		},
		Zones:       []string{"filtergeo.com."},
		ZoneConfigs: []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.filter.com.","ns":"ns1.filter.com.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"ww1",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":""},
            				{"ip":"127.0.0.2", "country":""},
            				{"ip":"127.0.0.3", "country":""},
            				{"ip":"127.0.0.4", "country":""},
            				{"ip":"127.0.0.5", "country":""},
            				{"ip":"127.0.0.6", "country":""}
						],
            			"filter":{"count":"multi","order":"none","geo_filter":"none"}}
					}`,
				},
				{"ww2",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":"US"},
            				{"ip":"127.0.0.2", "country":"GB"},
            				{"ip":"127.0.0.3", "country":"ES"},
							{"ip":"127.0.0.4", "country":""},
            				{"ip":"127.0.0.5", "country":""},
            				{"ip":"127.0.0.6", "country":""}
						],
            			"filter":{"count":"multi","order":"none","geo_filter":"country"}}
					}`,
				},
				{"ww3",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"192.30.252.225"},
            				{"ip":"94.76.229.204"},
            				{"ip":"84.88.14.229"},
							{"ip":"192.168.0.1"}
						],
            			"filter":{"count":"multi","order":"none","geo_filter":"location"}}
					}`,
				},
				{"ww4",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "asn":47447},
            				{"ip":"127.0.0.2", "asn":20776},
            				{"ip":"127.0.0.3", "asn":35470},
            				{"ip":"127.0.0.4", "asn":0},
            				{"ip":"127.0.0.5", "asn":0},
            				{"ip":"127.0.0.6", "asn":0}
						],
        				"filter":{"count":"multi", "order":"none","geo_filter":"asn"}}
					}`,
				},
				{"ww5",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":"DE", "asn":47447},
            				{"ip":"127.0.0.2", "country":"DE", "asn":20776},
            				{"ip":"127.0.0.3", "country":"DE", "asn":35470},
            				{"ip":"127.0.0.4", "country":"GB", "asn":0},
            				{"ip":"127.0.0.5", "country":"", "asn":0},
            				{"ip":"127.0.0.6", "country":"", "asn":0}
						],
        				"filter":{"count":"multi", "order":"none","geo_filter":"asn+country"}}
					}`,
				},
				{"ww6",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "asn":[47447,20776]},
            				{"ip":"127.0.0.2", "asn":[0,35470]},
            				{"ip":"127.0.0.3", "asn":35470},
            				{"ip":"127.0.0.4", "asn":0},
            				{"ip":"127.0.0.5", "asn":[]},
            				{"ip":"127.0.0.6"}
						],
        				"filter":{"count":"multi", "order":"none","geo_filter":"asn"}}
					}`,
				},
				{"ww7",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":["DE", "GB"]},
            				{"ip":"127.0.0.2", "country":["", "DE"]},
            				{"ip":"127.0.0.3", "country":"DE"},
            				{"ip":"127.0.0.4", "country":"CA"},
            				{"ip":"127.0.0.5", "country": ""},
            				{"ip":"127.0.0.6", "country": []},
            				{"ip":"127.0.0.7"}
						],
        				"filter":{"count":"multi", "order":"none","geo_filter":"country"}}
					}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "ww1.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww1.filtergeo.com. 300 IN A 127.0.0.1"),
					test.A("ww1.filtergeo.com. 300 IN A 127.0.0.2"),
					test.A("ww1.filtergeo.com. 300 IN A 127.0.0.3"),
					test.A("ww1.filtergeo.com. 300 IN A 127.0.0.4"),
					test.A("ww1.filtergeo.com. 300 IN A 127.0.0.5"),
					test.A("ww1.filtergeo.com. 300 IN A 127.0.0.6"),
				},
			},
			{
				Qname: "ww2.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww2.filtergeo.com. 300 IN A 127.0.0.4"),
					test.A("ww2.filtergeo.com. 300 IN A 127.0.0.5"),
					test.A("ww2.filtergeo.com. 300 IN A 127.0.0.6"),
				},
			},
			{
				Qname: "ww3.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww3.filtergeo.com. 300 IN A 192.168.0.1"),
				},
			},
			{
				Qname: "ww4.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww4.filtergeo.com. 300 IN A 127.0.0.4"),
					test.A("ww4.filtergeo.com. 300 IN A 127.0.0.5"),
					test.A("ww4.filtergeo.com. 300 IN A 127.0.0.6"),
				},
			},
			{
				Qname: "ww5.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww5.filtergeo.com. 300 IN A 127.0.0.5"),
					test.A("ww5.filtergeo.com. 300 IN A 127.0.0.6"),
				},
			},
			{
				Qname: "ww2.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww2.filtergeo.com. 300 IN A 127.0.0.2"),
				},
			},
			{
				Qname: "ww3.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww3.filtergeo.com. 300 IN A 192.30.252.225"),
				},
			},
			{
				Qname: "ww4.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww4.filtergeo.com. 300 IN A 127.0.0.1"),
				},
			},
			{
				Qname: "ww5.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww5.filtergeo.com. 300 IN A 127.0.0.1"),
				},
			},
			{
				Qname: "ww6.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww6.filtergeo.com. 300 IN A 127.0.0.1"),
				},
			},
			{
				Qname: "ww6.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww6.filtergeo.com. 300 IN A 127.0.0.2"),
					test.A("ww6.filtergeo.com. 300 IN A 127.0.0.3"),
				},
			},
			{
				Qname: "ww6.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww6.filtergeo.com. 300 IN A 127.0.0.2"),
					test.A("ww6.filtergeo.com. 300 IN A 127.0.0.4"),
					test.A("ww6.filtergeo.com. 300 IN A 127.0.0.5"),
					test.A("ww6.filtergeo.com. 300 IN A 127.0.0.6"),
				},
			},
			{
				Qname: "ww7.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.1"),
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.2"),
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.3"),
				},
			},
			{
				Qname: "ww7.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.1"),
				},
			},
			{
				Qname: "ww7.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.4"),
				},
			},
			{
				Qname: "ww7.filtergeo.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.2"),
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.5"),
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.6"),
					test.A("ww7.filtergeo.com. 300 IN A 127.0.0.7"),
				},
			},
		},
	},
	{
		Name:        "filter multi ip",
		Description: "ip filter functionality for multiple value results",
		Enabled:     true,
		Config:      defaultConfig,
		Initialize:  defaultInitialize,
		ApplyAndVerify: func(testCase *TestCase, handler *DnsRequestHandler, t *testing.T) {
			for i := 0; i < 10; i++ {
				tc := testCase.TestCases[0]
				r := tc.Msg()
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg

				if err := test.SortAndCheck(resp, tc); err != nil {
					fmt.Println(err)
					t.Fail()
				}
			}

			w1, w4, w10, w2, w20 := 0, 0, 0, 0, 0
			for i := 0; i < 10000; i++ {
				tc := testCase.TestCases[1]
				r := tc.Msg()
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg
				if len(resp.Answer) != 5 {
					fmt.Println("expected 5 results ", len(resp.Answer), " received")
					t.Fail()
				}

				resa := resp.Answer[0].(*dns.A)

				switch resa.A.String() {
				case "127.0.0.1":
					w1++
				case "127.0.0.2":
					w4++
				case "127.0.0.3":
					w10++
				case "127.0.0.4":
					w2++
				case "127.0.0.5":
					w20++
				}
			}
			// fmtPrintln(w1, w2, w4, w10, w20)
			if w1 > w2 || w2 > w4 || w4 > w10 || w10 > w20 {
				fmt.Println("bad ip weight balance")
				t.Fail()
			}

			rr := make([]int, 5)
			for i := 0; i < 10000; i++ {
				tc := testCase.TestCases[2]
				r := tc.Msg()
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg
				if len(resp.Answer) != 5 {
					fmt.Println("expected 5 results ", len(resp.Answer), " received")
					t.Fail()
				}

				resa := resp.Answer[0].(*dns.A)

				switch resa.A.String() {
				case "127.0.0.1":
					rr[0]++
				case "127.0.0.2":
					rr[1]++
				case "127.0.0.3":
					rr[2]++
				case "127.0.0.4":
					rr[3]++
				case "127.0.0.5":
					rr[4]++
				}
			}
			// fmt.Println(rr)
			for i := range rr {
				if rr[i] < 1500 || rr[i] > 2500 {
					fmt.Println("bad ip weight balance")
					t.Fail()
				}
			}
		},
		Zones:       []string{"filtermulti.com."},
		ZoneConfigs: []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.filtermulti.com.","ns":"ns1.filter.com.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"ww1",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":""},
            				{"ip":"127.0.0.2", "country":""},
            				{"ip":"127.0.0.3", "country":""},
            				{"ip":"127.0.0.4", "country":""},
            				{"ip":"127.0.0.5", "country":""},
            				{"ip":"127.0.0.6", "country":""}
						],
            			"filter":{"count":"multi","order":"none","geo_filter":"none"}}
					}`,
				},
				{"ww2",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":"", "weight":1},
            				{"ip":"127.0.0.2", "country":"", "weight":4},
            				{"ip":"127.0.0.3", "country":"", "weight":10},
            				{"ip":"127.0.0.4", "country":"", "weight":2},
            				{"ip":"127.0.0.5", "country":"", "weight":20}
						],
            			"filter":{"count":"multi","order":"weighted","geo_filter":"none"}}
					}`,
				},
				{"ww3",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":""},
            				{"ip":"127.0.0.2", "country":""},
            				{"ip":"127.0.0.3", "country":""},
            				{"ip":"127.0.0.4", "country":""},
            				{"ip":"127.0.0.5", "country":""}
						],
            			"filter":{"count":"multi","order":"rr","geo_filter":"none"}}
					}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "ww1.filtermulti.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww1.filtermulti.com. 300 IN A 127.0.0.1"),
					test.A("ww1.filtermulti.com. 300 IN A 127.0.0.2"),
					test.A("ww1.filtermulti.com. 300 IN A 127.0.0.3"),
					test.A("ww1.filtermulti.com. 300 IN A 127.0.0.4"),
					test.A("ww1.filtermulti.com. 300 IN A 127.0.0.5"),
					test.A("ww1.filtermulti.com. 300 IN A 127.0.0.6"),
				},
			},
			{
				Qname: "ww2.filtermulti.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{},
			},
			{
				Qname: "ww3.filtermulti.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{},
			},
		},
	},
	{
		Name:        "filter single ip",
		Description: "ip filter functionality for single value results",
		Enabled:     true,
		Config:      defaultConfig,
		Initialize:  defaultInitialize,
		ApplyAndVerify: func(testCase *TestCase, handler *DnsRequestHandler, t *testing.T) {
			for i := 0; i < 10; i++ {
				tc := testCase.TestCases[0]
				r := tc.Msg()
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg

				if err := test.SortAndCheck(resp, tc); err != nil {
					fmt.Println(err)
					t.Fail()
				}
			}

			w1, w4, w10, w2, w20 := 0, 0, 0, 0, 0
			for i := 0; i < 10000; i++ {
				tc := testCase.TestCases[1]
				r := tc.Msg()
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg
				if len(resp.Answer) != 1 {
					fmt.Println("expected 1 answer ", len(resp.Answer), " received")
					t.Fail()
				}

				resa := resp.Answer[0].(*dns.A)

				switch resa.A.String() {
				case "127.0.0.1":
					w1++
				case "127.0.0.2":
					w4++
				case "127.0.0.3":
					w10++
				case "127.0.0.4":
					w2++
				case "127.0.0.5":
					w20++
				}
			}
			// fmt.Println(w1, w2, w4, w10, w20)
			if w1 > w2 || w2 > w4 || w4 > w10 || w10 > w20 {
				fmt.Println("bad ip weight balance")
				t.Fail()
			}

			rr := make([]int, 5)
			for i := 0; i < 10000; i++ {
				tc := testCase.TestCases[2]
				r := tc.Msg()
				w := test.NewRecorder(&test.ResponseWriter{})
				state := NewRequestContext(w, r)
				handler.HandleRequest(state)

				resp := w.Msg
				if len(resp.Answer) != 1 {
					fmt.Println("expected 1 answer ", len(resp.Answer), " received")
					t.Fail()
				}

				resa := resp.Answer[0].(*dns.A)

				switch resa.A.String() {
				case "127.0.0.1":
					rr[0]++
				case "127.0.0.2":
					rr[1]++
				case "127.0.0.3":
					rr[2]++
				case "127.0.0.4":
					rr[3]++
				case "127.0.0.5":
					rr[4]++
				}
			}
			// fmt.Println(rr)
			for i := range rr {
				if rr[i] < 1500 || rr[i] > 2500 {
					fmt.Println("bad ip weight balance")
					t.Fail()
				}
			}
		},
		Zones:       []string{"filtersingle.com."},
		ZoneConfigs: []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.filtersingle.com.","ns":"ns1.filter.com.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"ww1",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":""},
            				{"ip":"127.0.0.2", "country":""},
            				{"ip":"127.0.0.3", "country":""},
            				{"ip":"127.0.0.4", "country":""},
            				{"ip":"127.0.0.5", "country":""},
            				{"ip":"127.0.0.6", "country":""}
						],
            			"filter":{"count":"single","order":"none","geo_filter":"none"}}
					}`,
				},
				{"ww2",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":"", "weight":1},
            				{"ip":"127.0.0.2", "country":"", "weight":4},
            				{"ip":"127.0.0.3", "country":"", "weight":10},
            				{"ip":"127.0.0.4", "country":"", "weight":2},
            				{"ip":"127.0.0.5", "country":"", "weight":20}
						],
            			"filter":{"count":"single","order":"weighted","geo_filter":"none"}}
					}`,
				},
				{"ww3",
					`{
						"a":{"ttl":300, "records":[
            				{"ip":"127.0.0.1", "country":""},
            				{"ip":"127.0.0.2", "country":""},
            				{"ip":"127.0.0.3", "country":""},
            				{"ip":"127.0.0.4", "country":""},
            				{"ip":"127.0.0.5", "country":""}
						],
            			"filter":{"count":"single","order":"rr","geo_filter":"none"}}
					}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "ww1.filtersingle.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ww1.filtersingle.com. 300 IN A 127.0.0.1"),
				},
			},
			{
				Qname: "ww2.filtersingle.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{},
			},
			{
				Qname: "ww3.filtersingle.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{},
			},
		},
	},
	{
		Name:        "cname upstream",
		Description: "cname should not leave authoritative zone",
		Enabled:     true,
		Config:      defaultConfig,
		Initialize:  defaultInitialize,
		ApplyAndVerify: func(testCase *TestCase, handler *DnsRequestHandler, t *testing.T) {
			tc := testCase.TestCases[0]
			r := tc.Msg()
			w := test.NewRecorder(&test.ResponseWriter{})
			state := NewRequestContext(w, r)
			handler.HandleRequest(state)

			resp := w.Msg
			// fmt.Println(resp)
			if resp.Rcode != dns.RcodeSuccess {
				fmt.Println("invalid rcode, expected : RcodeSuccess, received : ", dns.RcodeToString[resp.Rcode])
				t.Fail()
			}
			cname := resp.Answer[0].(*dns.CNAME)
			if cname.Target != "www.google.com." {
				fmt.Println("invalid cname target, expected : www.google.com. received : ", cname.Target)
				t.Fail()
			}
		},
		Zones:       []string{"upstreamcname.com."},
		ZoneConfigs: []string{`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.upstreamcname.com.","ns":"ns1.upstreamcname.com.","refresh":44,"retry":55,"expire":66}}`},
		Entries: [][][]string{
			{
				{"upstream",
					`{"cname":{"ttl":300, "host":"www.google.com"}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "upstream.upstreamcname.com.", Qtype: dns.TypeA,
			},
		},
	},
	{
		Name:           "cname outside domain",
		Description:    "cname should not leave current domain",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"inside.cnm.", "outside.cnm."},
		ZoneConfigs: []string{
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.inside.cnm.","ns":"ns1.inside.cnm.","refresh":44,"retry":55,"expire":66}}`,
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.outside.cnm.","ns":"ns1.outside.cnm.","refresh":44,"retry":55,"expire":66}}`,
		},
		Entries: [][][]string{
			{
				{"upstream",
					`{"cname":{"ttl":300, "host":"outside.cnm."}}`,
				},
			},
			{
				{"@",
					`{"a":{"ttl":300, "records":[{"ip":"127.0.0.6"}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "upstream.inside.cnm.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("upstream.inside.cnm. 300 IN CNAME outside.cnm."),
				},
			},
		},
	},
	{
		Name:           "cname loop",
		Description:    "should properly handler cname loop",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"loop.cnm."},
		ZoneConfigs:    []string{""},
		Entries: [][][]string{
			{
				{"w",
					`{"cname":{"ttl":300, "host":"w.loop.cnm."}}`,
				},
				{"w1",
					`{"cname":{"ttl":300, "host":"w2.loop.cnm."}}`,
				},
				{"w2",
					`{"cname":{"ttl":300, "host":"w1.loop.cnm."}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "w.loop.cnm.", Qtype: dns.TypeA,
				Rcode: dns.RcodeServerFailure,
			},
			{
				Qname: "w1.loop.cnm.", Qtype: dns.TypeA,
				Rcode: dns.RcodeServerFailure,
			},
			{
				Qname: "w2.loop.cnm.", Qtype: dns.TypeA,
				Rcode: dns.RcodeServerFailure,
			},
		},
	},
	{
		Name:           "zone matching",
		Description:    "zone should match with longest prefix",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"zone.zon.", "sub1.zone.zon."},
		ZoneConfigs:    []string{"", ""},
		Entries: [][][]string{
			{
				{"sub3.sub2",
					`{"a":{"ttl":300, "records":[{"ip":"1.1.1.1"}]}}`,
				},
				{"sub1",
					`{"a":{"ttl":300, "records":[{"ip":"2.2.2.2"}]}}`,
				},
				{"sub10",
					`{"a":{"ttl":300, "records":[{"ip":"5.5.5.5"}]}}`,
				},
				{"ub1",
					`{"a":{"ttl":300, "records":[{"ip":"6.6.6.6"}]}}`,
				},
			},
			{
				{"@",
					`{"a":{"ttl":300, "records":[{"ip":"3.3.3.3"}]}}`,
				},
				{"sub2",
					`{"a":{"ttl":300, "records":[{"ip":"4.4.4.4"}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "sub1.zone.zon.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("sub1.zone.zon. 300 IN A 3.3.3.3"),
				},
			},
			{
				Qname: "sub10.zone.zon.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("sub10.zone.zon. 300 IN A 5.5.5.5"),
				},
			},
			{
				Qname: "sub3.sub2.zone.zon.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("sub3.sub2.zone.zon. 300 IN A 1.1.1.1"),
				},
			},
			{
				Qname: "sub2.sub1.zone.zon.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("sub2.sub1.zone.zon. 300 IN A 4.4.4.4"),
				},
			},
			{
				Qname: "ub1.zone.zon.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("ub1.zone.zon. 300 IN A 6.6.6.6"),
				},
			},
		},
	},
	{
		Name:        "zone update",
		Description: "test zone update with redis event notification",
		Enabled:     true,
		Config:      defaultConfig,
		Initialize: func(testCase *TestCase) (handler *DnsRequestHandler, e error) {
			rd := uperdis.NewRedis(&testCase.Config.Redis)
			if err := rd.SetConfig("notify-keyspace-events", "AK"); err != nil {
				fmt.Println(err)
			}
			time.Sleep(time.Second)

			testCase.Config.CacheTimeout = 1
			h := NewHandler(&testCase.Config)
			if err := h.Redis.Del("*"); err != nil {
				fmt.Println(err)
			}
			for _, cmd := range testCase.Entries[0] {
				err := h.Redis.HSet("redins:zones:"+testCase.Zones[0], cmd[0], cmd[1])
				if err != nil {
					fmt.Printf("[ERROR] cannot connect to redis: %s", err)
					fmt.Println("1")
					return nil, err
				}
			}
			return h, nil
		},
		ApplyAndVerify: func(testCase *TestCase, handler *DnsRequestHandler, t *testing.T) {
			if err := handler.Redis.SAdd("redins:zones", testCase.Zones[0]); err != nil {
				fmt.Println(err)
			}
			time.Sleep(time.Millisecond * 10)
			tc := testCase.TestCases[0]
			r := tc.Msg()
			w := test.NewRecorder(&test.ResponseWriter{})
			state := NewRequestContext(w, r)
			handler.HandleRequest(state)

			resp := w.Msg
			if resp.Rcode != dns.RcodeSuccess {
				fmt.Println("invalid rcode, expected : RcodeSuccess, received : ", dns.RcodeToString[resp.Rcode])
				t.Fail()
			}

			if err := handler.Redis.SRem("redins:zones", testCase.Zones[0]); err != nil {
				fmt.Println(err)
			}
			time.Sleep(time.Millisecond * 1500)
			tc = testCase.TestCases[0]
			r = tc.Msg()
			w = test.NewRecorder(&test.ResponseWriter{})
			state = NewRequestContext(w, r)
			handler.HandleRequest(state)

			resp = w.Msg
			if resp.Rcode != dns.RcodeNotAuth {
				fmt.Println("invalid rcode, expected : RcodeNotAuth, received : ", dns.RcodeToString[resp.Rcode])
				t.Fail()
			}
		},
		Zones:       []string{"zone1.com."},
		ZoneConfigs: []string{""},
		Entries: [][][]string{
			{
				{
					"www",
					`{"a":{"ttl":300, "records":[{"ip":"1.1.1.1"}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "www.zone1.com", Qtype: dns.TypeA,
			},
		},
	},
	{
		Name:           "cname noauth",
		Description:    "cname following should stop and return results when reaching notauth zone",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"auth.zon."},
		ZoneConfigs:    []string{""},
		Entries: [][][]string{
			{
				{"w1",
					`{"cname":{"ttl":300, "host":"w2.auth.zon."}}`,
				},
				{"w2",
					`{"cname":{"ttl":300, "host":"noauth.zon."}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "w1.auth.zon.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("w1.auth.zon.	300	IN	CNAME	w2.auth.zon."),
					test.CNAME("w2.auth.zon.	300	IN	CNAME	noauth.zon."),
				},
				Rcode: dns.RcodeSuccess,
			},
		},
	},
	{
		Name:           "delegation",
		Description:    "test subdomain delegation",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"delegation.zon."},
		ZoneConfigs:    []string{""},
		Entries: [][][]string{
			{
				{"glue",
					`{"ns":{"ttl":300, "records":[{"host":"ns1.glue.delegation.zon."},{"host":"ns2.glue.delegation.zon."}]}}`,
				},
				{"noglue",
					`{"ns":{"ttl":300, "records":[{"host":"ns1.delegated.zon."},{"host":"ns2.delegated.zon."}]}}`,
				},
				{"ns1.glue",
					`{"a":{"ttl":300, "records":[{"ip":"1.2.3.4"}]}}`,
				},
				{"ns2.glue",
					`{"a":{"ttl":300, "records":[{"ip":"5.6.7.8"}]}}`,
				},
				{"cname",
					`{"cname":{"ttl":300, "host":"glue.delegation.zon."}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "glue.delegation.zon.",
				Qtype: dns.TypeA,
				Rcode: dns.RcodeNotAuth,
				Ns: []dns.RR{
					test.NS("glue.delegation.zon. 300 IN NS ns1.glue.delegation.zon."),
					test.NS("glue.delegation.zon. 300 IN NS ns2.glue.delegation.zon."),
				},
				Extra: []dns.RR{
					test.A("ns1.glue.delegation.zon. 300 IN A 1.2.3.4"),
					test.A("ns2.glue.delegation.zon. 300 IN A 5.6.7.8"),
				},
			},
			{
				Qname: "noglue.delegation.zon.",
				Qtype: dns.TypeA,
				Rcode: dns.RcodeNotAuth,
				Ns: []dns.RR{
					test.NS("noglue.delegation.zon. 300 IN NS ns1.delegated.zon."),
					test.NS("noglue.delegation.zon. 300 IN NS ns2.delegated.zon."),
				},
			},
			{
				Qname: "cname.delegation.zon.",
				Qtype: dns.TypeA,
				Rcode: dns.RcodeNotAuth,
				Answer: []dns.RR{
					test.CNAME("cname.delegation.zon. 300 IN CNAME glue.delegation.zon."),
				},
				Ns: []dns.RR{
					test.NS("glue.delegation.zon. 300 IN NS ns1.glue.delegation.zon."),
					test.NS("glue.delegation.zon. 300 IN NS ns2.glue.delegation.zon."),
				},
				Extra: []dns.RR{
					test.A("ns1.glue.delegation.zon. 300 IN A 1.2.3.4"),
					test.A("ns2.glue.delegation.zon. 300 IN A 5.6.7.8"),
				},
			},
		},
	},
	{
		Name:           "label matching",
		Description:    "test correct label matching",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"zone1.com.", "zone2.com.", "zone3.com."},
		ZoneConfigs:    []string{"", "", ""},
		Entries: [][][]string{
			{
				{"@",
					`{"a":{"ttl":300, "records":[{"ip":"1.1.1.1"}]}}`,
				},
				{"www",
					`{"a":{"ttl":300, "records":[{"ip":"1.1.1.2"}]}}`,
				},
			},
			{
				{"@",
					`{"a":{"ttl":300, "records":[{"ip":"2.2.2.1"}]}}`,
				},
				{"www",
					`{"a":{"ttl":300, "records":[{"ip":"2.2.2.2"}]}}`,
				},
				{"zone1.com",
					`{"a":{"ttl":300, "records":[{"ip":"2.2.2.3"}]}}`,
				},
				{"www.zone1",
					`{"a":{"ttl":300, "records":[{"ip":"2.2.2.4"}]}}`,
				},
				{"www.zone1.com",
					`{"a":{"ttl":300, "records":[{"ip":"2.2.2.5"}]}}`,
				},
			},
			{
				{"@",
					`{"a":{"ttl":300, "records":[{"ip":"3.3.3.1"}]}}`,
				},
				{"www",
					`{"a":{"ttl":300, "records":[{"ip":"3.3.3.2"}]}}`,
				},
				{"zone3.com",
					`{"a":{"ttl":300, "records":[{"ip":"3.3.3.3"}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "zone1.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("zone1.com. 300 IN A 1.1.1.1"),
				},
			},
			{
				Qname: "www.zone1.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("www.zone1.com. 300 IN A 1.1.1.2"),
				},
			},
			{
				Qname: "zone2.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("zone2.com. 300 IN A 2.2.2.1"),
				},
			},
			{
				Qname: "www.zone2.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("www.zone2.com. 300 IN A 2.2.2.2"),
				},
			},
			{
				Qname: "zone1.com.zone2.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("zone1.com.zone2.com. 300 IN A 2.2.2.3"),
				},
			},
			{
				Qname: "www.zone1.zone2.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("www.zone1.zone2.com. 300 IN A 2.2.2.4"),
				},
			},
			{
				Qname: "www.zone1.com.zone2.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("www.zone1.com.zone2.com. 300 IN A 2.2.2.5"),
				},
			},
			{
				Qname: "zone3.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("zone3.com. 300 IN A 3.3.3.1"),
				},
			},
			{
				Qname: "www.zone3.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("www.zone3.com. 300 IN A 3.3.3.2"),
				},
			},
			{
				Qname: "zone3.com.zone3.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("zone3.com.zone3.com. 300 IN A 3.3.3.3"),
				},
			},
		},
	},
	{
		Name:           "cname flattening leaving zone",
		Description:    "test correct response when reaching a cname pointing outside current zone",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"flat.com.", "noflat.com."},
		ZoneConfigs: []string{
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.flat.com.","ns":"ns1.flat.com.","refresh":44,"retry":55,"expire":66},"cname_flattening":true}}`,
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.noflat.com.","ns":"ns1.noflat.com.","refresh":44,"retry":55,"expire":66},,"cname_flattening":false}}`,
		},
		Entries: [][][]string{
			{
				{"www",
					`{"cname":{"ttl":300, "host":"anotherzone.com."}}`,
				},
			},
			{
				{"www",
					`{"cname":{"ttl":300, "host":"anotherzone.com."}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "www.flat.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("www.flat.com. 300 IN CNAME anotherzone.com."),
				},
			},
			{
				Qname: "www.noflat.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("www.noflat.com. 300 IN CNAME anotherzone.com."),
				},
			},
		},
	},
	{
		Name:           "ANAME ttl",
		Description:    "test ttl value for aname queries",
		Enabled:        true,
		Config:         defaultConfig,
		Initialize:     defaultInitialize,
		ApplyAndVerify: defaultApplyAndVerify,
		Zones:          []string{"arvancloud.com.", "arvan.an."},
		ZoneConfigs: []string{
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.arvancloud.com.","ns":"ns1.arvancloud.com.","refresh":44,"retry":55,"expire":66}}`,
			`{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.arvan.an.","ns":"ns1.arvan.an.","refresh":44,"retry":55,"expire":66}}`,
		},
		Entries: [][][]string{
			{
				{"@",
					`{"aname":{"location":"aname.arvan.an."}}`,
				},
				{"upstream",
					`{"aname":{"location":"dns.msftncsi.com."}}`,
				},
			},
			{
				{"aname",
					`{"a":{"ttl":180, "records":[{"ip":"6.5.6.5"}]}, "aaaa":{"ttl":300, "records":[{"ip":"::1"}]}}`,
				},
			},
		},
		TestCases: []test.Case{
			{
				Qname: "arvancloud.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("arvancloud.com. 180 IN A 6.5.6.5"),
				},
			},
			{
				Qname: "upstream.arvancloud.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("upstream.arvancloud.com. 303 IN A 131.107.255.255"),
				},
			},
		},
	},
}

func center(s string, w int) string {
	return fmt.Sprintf("%[1]*s", -w, fmt.Sprintf("%[1]*s", (w+len(s))/2, s))
}

func TestAll(t *testing.T) {
	for _, testCase := range testCases {
		if !testCase.Enabled {
			continue
		}
		fmt.Println(">>> ", center(testCase.Name, 70), " <<<")
		fmt.Println(testCase.Description)
		fmt.Println(strings.Repeat("-", 80))
		h, err := testCase.Initialize(testCase)
		if err != nil {
			fmt.Println("initialization failed : ", err)
			t.Fail()
		}
		testCase.ApplyAndVerify(testCase, h, t)
	}
}
