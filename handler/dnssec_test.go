package handler

import (
	"arvancloud/redins/test"
	"fmt"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	"github.com/miekg/dns"
	"log"
	"sort"
	"testing"
)

var dnssecZone = "dnssec_test.com."

var dnssecConfig = `{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.dnssec_test.com.","ns":"ns1.dnssec_test.com.","refresh":44,"retry":55,"expire":66},"dnssec": true}`
var dnssecEntries = [][]string{
	{"@",
		`{"ns":{"ttl":300,"records":[{"host":"ns1.dnssec_test.com."},{"host":"ns2.dnssec_test.com."}]}}`,
	},
	{"x",
		`{
            "a":{"ttl":300, "records":[{"ip":"1.2.3.4", "country":"ES"},{"ip":"5.6.7.8", "country":""}]},
            "aaaa":{"ttl":300, "records":[{"ip":"::1"}]},
            "txt":{"ttl":300, "records":[{"text":"foo"},{"text":"bar"}]},
            "mx":{"ttl":300, "records":[{"host":"mx1.dnssec_test.com.", "preference":10},{"host":"mx2.dnssec_test.com.", "preference":10}]},
            "srv":{"ttl":300, "records":[{"target":"sip.dnssec_test.com.","port":555,"priority":10,"weight":100}]}
        }`,
	},
	{"y",
		`{"ns":{"ttl":300, "records":[{"host":"ns1.dnssec_test.com."},{"host":"ns2.dnssec_test.com."}]}}`,
	},
	{"*",
		`{"txt":{"ttl":300,"records":[{"text":"wildcard text"}]}}`,
	},
	{"a",
		`{"a":{"ttl":300,"records":[{"ip":"129.0.2.1"}]},"txt":{"ttl":300,"records":[{"text":"a text"}]}}`,
	},
	{"d",
		`{"a":{"ttl":300,"records":[{"ip":"129.0.2.1"}]},"txt":{"ttl":300,"records":[{"text":"d text"}]}}`,
	},
	{"c1",
		`{"cname":{"ttl":300, "host":"c2.dnssec_test.com."}}`,
	},
	{"c2",
		`{"cname":{"ttl":300, "host":"c3.dnssec_test.com."}}`,
	},
	{"c3",
		`{"cname":{"ttl":300, "host":"a.dnssec_test.com."}}`,
	},
	{"w",
		`{"cname":{"ttl":300, "host":"w.a.dnssec_test.com."}}`,
	},
	{"*.a",
		`{"cname":{"ttl":300, "host":"w.b.dnssec_test.com."}}`,
	},
	{"*.b",
		`{"cname":{"ttl":300, "host":"w.c.dnssec_test.com."}}`,
	},
	{"*.c",
		`{"a":{"ttl":300, "records":[{"ip":"129.0.2.1"}]}}`,
	},
}

var zskPriv = `Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: oqwXm/EF8q6p5Rrj66Bbft+0Vk7Kj6TuvZp4nNl0htiT/8/92kIcri5gbxnV2v+p6jXYQI1Vx/vqP5cB0kPzjUQuJFVpm14fxOp89D6N0fPXR7xJ+SHs5nigHBIJdaP5
PublicExponent: AQAB
PrivateExponent: fJBa48aET3kAD7evn9aDOXwDk7Nx2NzrE7Uddr3tRPTDH7gdIuxNGfPZVDnsUG5EbX2JJf3JQsD7YXeQ+BGyytIi0ZTq8jsU63Np9hjheFx+IWSIz6S4JGnFKWRWUvuh
Prime1: 1c0EgZCXitPsdtEURwj1okEgzN9ze+QRP8adz0t+0s6ptB+bG3+YrhbzXcexE0tv
Prime2: wseiokM5ugXX0ZKy+8+lvumEZ94gM8Tyc031tFc1RRqIzB67k7139r/liNJoGXMX
Exponent1: WZyl79x3+CNdcGuv8RorQofDxLs/v0TXigCosnM1RAyFCs9Yhs0TZJyQAtWpPaoX
Exponent2: GXGcpBemBc/Xlm/UY6KHYz375tmUWU7j4P4RF6LAuasyrX9iP3Vjo18D6/CYWqK3
Coefficient: GhzOVUQcUJkvbYc9/+9MZngzDCeoetXDR6IILqG0/Rmt7FHWwSD7nOSoUUE5GslF
Created: 20180717134704
Publish: 20180717134704
Activate: 20180717134704
`

var zskPub = "dnssec_test.com. IN DNSKEY 256 3 5 AwEAAaKsF5vxBfKuqeUa4+ugW37ftFZOyo+k7r2aeJzZdIbYk//P/dpC HK4uYG8Z1dr/qeo12ECNVcf76j+XAdJD841ELiRVaZteH8TqfPQ+jdHz 10e8Sfkh7OZ4oBwSCXWj+Q=="

var dnskeyQuery = test.Case{
	Do:    true,
	Qname: "dnssec_test.com", Qtype: dns.TypeDNSKEY,
}

var kskPriv = `Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: 5WuOIP3GHID5Qmed6L+2ehBCkusTAXNv9uUfpzzTJHsA+bBesZSFsRNzMAV2drM7fApcL5IgNqrhb5twxu1/+cZj2Ld3PALbkENzn/erTl4A4uQdSWdkj8KnaLiJQPaT
PublicExponent: AQAB
PrivateExponent: BxiDhduzg/AtRXOE+8zqLO5R0M96gAH9BYripr6H3Un8prxgwWdRlz99wY95sYQrlNWr+4hhvikuOc9FjpXGg8E63iCNaZsVd/l8RvLGCtRPMtOEWhOecKe3kktHMUxp
Prime1: 9EWCZ3wwK2q7nsts12QuFGBTH/SOgHiaw9ieAn+mOA679BlIWXjeUoA5Hlj+ob31
Prime2: 8G9/lMOO+xgwjU7lQ5teFGmmNb2JXB/nP3pWQURdy+Chnb8wrcHALJGW1G7DAMVn
Exponent1: jroSoQ7iQmwh5n3sQcpqVkOWLmTB4vUVUPvAD6uwXq7VSaKAMK88EC6VsVLErZMF
Exponent2: qIlPwgTOzf3n0rXSCXD4IpDoHFWO2o/Wdm2X1spIgWglgcEKK1JcFiG7u48ki/7T
Coefficient: QCGY0yr+kkmOZfUoL9YCCgau/xjyEPRZgiGTfIy0PtGGMDKfUswJ+1KWI9Jue3E5
Created: 20190518113600
Publish: 20190518113600
Activate: 20190518113600
`

var kskPub = "dnssec_test.com. IN DNSKEY 257 3 5 AwEAAeVrjiD9xhyA+UJnnei/tnoQQpLrEwFzb/blH6c80yR7APmwXrGU hbETczAFdnazO3wKXC+SIDaq4W+bcMbtf/nGY9i3dzwC25BDc5/3q05e AOLkHUlnZI/Cp2i4iUD2kw=="

var dnssecTestCases = []test.Case{
	{
		Qname: "dnssec_test.com.", Qtype: dns.TypeDNSKEY,
		Answer: []dns.RR{
			test.DNSKEY("dnssec_test.com.	3600	IN	DNSKEY	256 3 5 AwEAAaKsF5vxBfKuqeUa4+ugW37ftFZOyo+k7r2aeJzZdIbYk//P/dpCHK4uYG8Z1dr/qeo12ECNVcf76j+XAdJD841ELiRVaZteH8TqfPQ+jdHz10e8Sfkh7OZ4oBwSCXWj+Q=="),
			test.DNSKEY("dnssec_test.com.	3600	IN	DNSKEY	257 3 5 AwEAAeVrjiD9xhyA+UJnnei/tnoQQpLrEwFzb/blH6c80yR7APmwXrGUhbETczAFdnazO3wKXC+SIDaq4W+bcMbtf/nGY9i3dzwC25BDc5/3q05eAOLkHUlnZI/Cp2i4iUD2kw=="),
			test.RRSIG("dnssec_test.com.	3600	IN	RRSIG	DNSKEY 5 2 3600 20190527081109 20190519051109 37456 dnssec_test.com. oVwtVEf9eOkcuSJlsH0OSBUvLOxgKM1pIAe7v717oRyCoyC+FIG5uGsdrZWhgklh/fpEmRdJQ+nHXKWT/son8zvxAoskuIIp49wwgvcS400IoHiyjIY0BHNTFPvsPdy0"),
		},
		Do: true,
	},
	{
		Qname: "x.dnssec_test.com.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("x.dnssec_test.com. 300 IN A 1.2.3.4"),
			test.A("x.dnssec_test.com. 300 IN A 5.6.7.8"),
		},
	},
	{
		Qname: "x.dnssec_test.com.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("x.dnssec_test.com. 300 IN A 1.2.3.4"),
			test.A("x.dnssec_test.com. 300 IN A 5.6.7.8"),
			test.RRSIG("x.dnssec_test.com.	300	IN	RRSIG	A 5 3 300 20180726080503 20180718050503 22548 dnssec_test.com. b/rdGOnMQzKX4K9c3CLvJYb2ErFlrShy8vBh86Y28t1RRnN9OCj7L1AGhr+5xEge3mpuRNd2djXFh7CwZmAOm6R0/acRP1mw1RnlSANhaVt1Enr57c6+5grPgn7e45X3"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	{
		Qname: "x.dnssec_test.com.", Qtype: dns.TypeAAAA,
		Answer: []dns.RR{
			test.AAAA("x.dnssec_test.com. 300 IN AAAA ::1"),
			test.RRSIG("x.dnssec_test.com.	300	IN	RRSIG	AAAA 5 3 300 20180726102716 20180718072716 22548 dnssec_test.com. Bl6GjbEY2jXyWhVuQzehQs4RVvrIRvLz72eXjvRKXTg6BGmcZF7CyZo1+R2w3p83gAA0yhs6UnSD/GMC5zmLeR5/8LiTzWa0S5f5xZNHwWNEUtrtnS7nGCCFDXfLUI3n"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// TXT Test
	{
		Qname: "x.dnssec_test.com.", Qtype: dns.TypeTXT,
		Answer: []dns.RR{
			test.TXT("x.dnssec_test.com. 300 IN TXT bar"),
			test.TXT("x.dnssec_test.com. 300 IN TXT foo"),
			test.RRSIG("x.dnssec_test.com.	300	IN	RRSIG	TXT 5 3 300 20180726102908 20180718072908 22548 dnssec_test.com. NND6mWXgQ1CY/KTsgPcjvty7FdLCFQdoHQ6Rmyv2hpPg12xTmAokB/TScTeL+zhvtt+9ktYnErspZc3LVoyPqZ8TYppHHoEXDR8OpyqmVcTPx/fzRuW5zmuUpofnhlV6"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// NS Test
	{
		Qname: "dnssec_test.com.", Qtype: dns.TypeNS,
		Answer: []dns.RR{
			test.NS("dnssec_test.com. 300 IN NS ns1.dnssec_test.com."),
			test.NS("dnssec_test.com. 300 IN NS ns2.dnssec_test.com."),
			test.RRSIG("dnssec_test.com.	300	IN	RRSIG	NS 5 2 300 20191122140218 20191114110218 22548 dnssec_test.com. DK9giOXPadNyDfFtsPjEd9JpWGIeCyIOgDDwzvgsYc/k/Q5blgtWBNxJ Fk0aPqj6M15RFTig2nA3uEJpEJx7OAj5zzSSTqyPozT/qrmPMWdxJcuK yaJ+CH+Ws9wJsM3S"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// MX Test
	{
		Qname: "x.dnssec_test.com.", Qtype: dns.TypeMX,
		Answer: []dns.RR{
			test.MX("x.dnssec_test.com. 300 IN MX 10 mx1.dnssec_test.com."),
			test.MX("x.dnssec_test.com. 300 IN MX 10 mx2.dnssec_test.com."),
			test.RRSIG("x.dnssec_test.com.	300	IN	RRSIG	MX 5 3 300 20180726104823 20180718074823 22548 dnssec_test.com. I0il28K7OmjA/hRwV/uPyieeg+EnpxRQmcUvZ1JsijIAqf6FVqDbysgrZfzZBheizMuLsEjPmmVTJrl34Y1ZEHxwD9oxgxWSDQ4L7kHLUeOSTRA73maHOtr+Sypygw6E"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// SRV Test
	{
		Qname: "x.dnssec_test.com.", Qtype: dns.TypeSRV,
		Answer: []dns.RR{
			test.SRV("x.dnssec_test.com. 300 IN SRV 10 100 555 sip.dnssec_test.com."),
			test.RRSIG("x.dnssec_test.com.	300	IN	RRSIG	SRV 5 3 300 20180726104916 20180718074916 22548 dnssec_test.com. hwyeNmMQ6K6Ja/ogepGQvGEyEiBeCd7Suhb6CL/uEREuREq1wcr9QhS2s3yKy9ZhjO9xs2x38vSSZHvRBvTjVxMIpPaQuxcWI02s/NgVLkRA5H0LpBPE5pyXDxTmtavV"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// SOA Test
	{
		Qname: "dnssec_test.com.", Qtype: dns.TypeSOA,
		Answer: []dns.RR{
			test.SOA("dnssec_test.com.	300	IN	SOA	ns1.dnssec_test.com. hostmaster.dnssec_test.com. 1533107401 44 55 66 100"),
			test.RRSIG("dnssec_test.com.	300	IN	RRSIG	SOA 5 2 300 20180809071001 20180801041001 22548 dnssec_test.com. O4+6kPz9sr26RDZLy9MUoQRFweEzVZJ8JvQAJ+3mcZ/xO8z4KKNRb3Gpf7sWyoQk6Bd476VkZHbkbEf9SRptDqDHPV5MxMDUa3AtbdwUkRaVDidL95B4KDcno5FOU55I"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// NXDomain Test
	{
		Qname: "nxdomain.x.dnssec_test.com.", Qtype: dns.TypeAAAA,
		Ns: []dns.RR{
			test.SOA("dnssec_test.com.	300	IN	SOA	ns1.dnssec_test.com. hostmaster.dnssec_test.com. 1533107621 44 55 66 100"),
			test.RRSIG("dnssec_test.com.	300	IN	RRSIG	SOA 5 2 300 20180809071341 20180801041341 22548 dnssec_test.com. hJ6GxQo46z5hxBV48hs5Ab1tdfCJ1S7wxIIoI3cksCtf+dqv/eLmlxGH0KuEabAPWhp9VqyjjQYxvSP/0gH0Z/BwYxoghxrROuqHqiIbkbM8wvgLHBwNv+vA4xXUN/Ej"),
			test.NSEC("nxdomain.x.dnssec_test.com.	100	IN	NSEC	\\000.nxdomain.x.dnssec_test.com. RRSIG NSEC"),
			test.RRSIG("nxdomain.x.dnssec_test.com.	100	IN	RRSIG	NSEC 5 4 100 20180809115341 20180801085341 22548 dnssec_test.com. cHqIhWUalUAib9cpVd+4XLLzxrm6zKiQKLWs1/2T4dNhaS/CAkIXY6so0YDpsm0wgS2McpVd/GL+2fPDEb0MXJYyTfX8mzn5i49riQjEiHbmlL7oZfXCUKxKTRYczxjf"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// wildcard Test
	{
		Qname: "z.dnssec_test.com.", Qtype: dns.TypeTXT,
		Answer: []dns.RR{
			test.TXT("z.dnssec_test.com. 300 IN TXT \"wildcard text\""),
			test.RRSIG("z.dnssec_test.com.	300	IN	RRSIG	TXT 5 3 300 20180731095235 20180723065235 22548 dnssec_test.com. YCmkNMLkg6qtey+9+Yt+Jq0V1itDF9Gw8rodPk82b486jE22xxleLq8zcwne8Xekp57H/9Sk5mmTzczWTZQAUauUQF+o2QzLkgiI5vr0gtC5Y3fraRCDclo9/8IQ2yEs"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// cname flattening test
	{
		Qname: "c1.dnssec_test.com.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.CNAME("c1.dnssec_test.com.	300	IN	CNAME	c2.dnssec_test.com."),
			test.RRSIG("c1.dnssec_test.com.	300	IN	RRSIG	CNAME 5 3 300 20180731105909 20180723075909 22548 dnssec_test.com. lvcR8ruQHs3qnQd+SZEr8LsTfIbcPQr7G6xHprp0vgcjstnb+0egDgJNJfJZHanwn3Ya/72Bqww3cDpIFV/8/kSVlSYz4cMb9hJR8Cq+ttFsRAFgSEA0cFxX4fG6WG85"),
			test.CNAME("c2.dnssec_test.com.	300	IN	CNAME	c3.dnssec_test.com."),
			test.RRSIG("c2.dnssec_test.com.	300	IN	RRSIG	CNAME 5 3 300 20180731105909 20180723075909 22548 dnssec_test.com. YNSfNKSz5LOhhoeGmZ77aLE/Z/QZEnkz5UD8g9fxalAkogVKR/bAEYcNkxMh5u5wjTH9/HnWMBLkK56FjmXIrI5KeY3paXWJ85QJJGeTAcwj/uLgF0Qq+nVCqldudmN+"),
			test.CNAME("c3.dnssec_test.com.	300	IN	CNAME	a.dnssec_test.com."),
			test.RRSIG("c3.dnssec_test.com.	300	IN	RRSIG	CNAME 5 3 300 20180731105909 20180723075909 22548 dnssec_test.com. FFE4WsYh2sAsYlewm1/1/GSo0oeFwJPt+35C2k/6nB+w+9/rBcRXwS8kfEvCuJS4GxcYV/vCLncQxNY5OI7Q5Vaxyo1OV+xWYY7OKTS7MBivUdlNvquMMkgIqZwqYdFl"),
			test.A("a.dnssec_test.com.	300	IN	A	129.0.2.1"),
			test.RRSIG("a.dnssec_test.com.	300	IN	RRSIG	A 5 3 300 20180731105909 20180723075909 22548 dnssec_test.com. fKHuZTJgweFmBmASxDiZYr8r300CtAmJ03ICKAHS8FkATjLvUyZxWqjI/fExZz277pZ0FMGRiwIb7o6aI31fpAahtU1E0Mo7J0sXjVATCBhME0S88DDuPXgrOMzu8f7K"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
	// CNAME flattening + wildcard Test
	{
		Qname: "w.dnssec_test.com.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.CNAME("w.a.dnssec_test.com.	300	IN	CNAME	w.b.dnssec_test.com."),
			test.RRSIG("w.a.dnssec_test.com.	300	IN	RRSIG	CNAME 5 4 300 20180801064612 20180724034612 22548 dnssec_test.com. OZlpQZTJH6KjNJPDuB/YPQORgwRfPpGz5FR0AReqRizAJMOjPSNjcmzpjpFXi7N5Hg+x+15RD0pnE8yL6XXSrg5pNsQo7p9XJa/6H9AL9OGMgYcOJe5FRJwHN9XXGrVr"),
			test.CNAME("w.b.dnssec_test.com.	300	IN	CNAME	w.c.dnssec_test.com."),
			test.RRSIG("w.b.dnssec_test.com.	300	IN	RRSIG	CNAME 5 4 300 20180801064612 20180724034612 22548 dnssec_test.com. VMs35joPFxyRrWtz1gyGRKju9j6p7MrQihOwU8m7cmCKmNT/6e58qS3OYYnp6tH34IxJnf+DZGapL07pMwSe+JyaOpsSirTmmytKU6NRQoidijKa7QkMXtXpY1l70Fga"),
			test.A("w.c.dnssec_test.com.	300	IN	A	129.0.2.1"),
			test.RRSIG("w.c.dnssec_test.com.	300	IN	RRSIG	A 5 4 300 20180801064612 20180724034612 22548 dnssec_test.com. LrrMYhyADHnznyVFx/DKqpteVrRqqOIgkrWzpOO3AI8Mx1xTfNqy6xMi/ngZPRfUuLHqkp9dyYhJN1qHrRwu2rJw1P+X3n7oD3hDL982ppB3hYAWPzTcwYO0C5848AQD"),
			test.CNAME("w.dnssec_test.com.	300	IN	CNAME	w.a.dnssec_test.com."),
			test.RRSIG("w.dnssec_test.com.	300	IN	RRSIG	CNAME 5 3 300 20180801064612 20180724034612 22548 dnssec_test.com. fgaoAooAffMg2apxMqmQBKgVVTGx+PaOo7ik61DvsG9UP7EeBQ7K0bNGxYlcQHDv7aZdLwtTU5OpLk2UCbZPhVAr69Irdr0RYOc+/Jzgw0u+iWU2o0ERxUG9ICiB+Ix8"),
		},
		Do: true,
		Extra: []dns.RR{
			test.OPT(4096, true),
		},
	},
}

var dnssecTestConfig = DnsRequestHandlerConfig{
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
	},
}

func TestDNSSEC(t *testing.T) {
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)

	h := NewHandler(&dnssecTestConfig)

	if err := h.Redis.Del(dnssecZone); err != nil {
		fmt.Println(err)
	}
	for _, cmd := range dnssecEntries {
		err := h.Redis.HSet("redins:zones:"+dnssecZone, cmd[0], cmd[1])
		if err != nil {
			log.Printf("[ERROR] cannot connect to redis: %s", err)
			t.Fail()
		}
	}
	if err := h.Redis.Set("redins:zones:"+dnssecZone+":config", dnssecConfig); err != nil {
		fmt.Println(err)
	}
	if err := h.Redis.Set("redins:zones:"+dnssecZone+":zsk:pub", zskPub); err != nil {
		fmt.Println(err)
	}
	if err := h.Redis.Set("redins:zones:"+dnssecZone+":zsk:priv", zskPriv); err != nil {
		fmt.Println(err)
	}
	if err := h.Redis.Set("redins:zones:"+dnssecZone+":ksk:pub", kskPub); err != nil {
		fmt.Println(err)
	}
	if err := h.Redis.Set("redins:zones:"+dnssecZone+":ksk:priv", kskPriv); err != nil {
		fmt.Println(err)
	}
	if err := h.Redis.SAdd("redins:zones", dnssecZone); err != nil {
		fmt.Println(err)
	}
	h.LoadZones()

	var zsk dns.RR
	var ksk dns.RR
	{
		r := dnskeyQuery.Msg()
		w := test.NewRecorder(&test.ResponseWriter{})
		state := NewRequestContext(w, r)
		h.HandleRequest(state)
		resp := w.Msg
		// fmt.Println(resp.Answer)
		for _, answer := range resp.Answer {
			if key, ok := answer.(*dns.DNSKEY); ok {
				if key.Flags == 256 {
					zsk = answer
				} else if key.Flags == 257 {
					ksk = answer
				}
			}
		}
	}
	// fmt.Println("zsk is ", zsk.String())
	// fmt.Println("ksk is ", ksk.String())

	for i, tc0 := range dnssecTestCases {
		// fmt.Println(i)
		tc := test.Case{
			Qname: dnssecTestCases[i].Qname, Qtype: dnssecTestCases[i].Qtype,
			Answer: make([]dns.RR, len(dnssecTestCases[i].Answer)),
			Ns:     make([]dns.RR, len(dnssecTestCases[i].Ns)),
			Do:     dnssecTestCases[i].Do,
			Extra: []dns.RR{
				test.OPT(4096, true),
			},
		}
		if !tc.Do {
			tc.Extra = []dns.RR{}
		}
		copy(tc.Answer, dnssecTestCases[i].Answer)
		copy(tc.Ns, dnssecTestCases[i].Ns)
		sort.Sort(test.RRSet(tc.Answer))
		sort.Sort(test.RRSet(tc.Ns))

		r := tc.Msg()
		w := test.NewRecorder(&test.ResponseWriter{})
		state := NewRequestContext(w, r)
		h.HandleRequest(state)
		resp := w.Msg
		for _, rrs := range [][]dns.RR{tc0.Answer, tc0.Ns, resp.Answer, resp.Ns} {
			s := 0
			e := 1
			for {
				if s >= len(rrs) || e >= len(rrs) {
					break
				}
				if rrsig, ok := rrs[e].(*dns.RRSIG); ok {
					// fmt.Printf("s = %d, e = %d\n", s, e)
					if tc.Qtype == dns.TypeDNSKEY {
						if rrsig.Verify(ksk.(*dns.DNSKEY), rrs[s:e]) != nil {
							fmt.Println("fail")
							t.Fail()
						}
					} else {
						if rrsig.Verify(zsk.(*dns.DNSKEY), rrs[s:e]) != nil {
							fmt.Println("fail")
							t.Fail()
						}
					}
					s = e + 1
					e = s + 1
				} else {
					e++
				}
			}
		}
		//fmt.Println("dddd")
		if err := test.SortAndCheck(resp, tc); err != nil {
			fmt.Println(err, resp.Answer, tc.Answer)
			t.Fail()
		}
		//fmt.Println("xxxx")
	}


}
