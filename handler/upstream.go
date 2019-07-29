package handler

import (
	"strconv"
	"time"

	"github.com/hawell/logger"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

type UpstreamConnection struct {
	client        *dns.Client
	connectionStr string
}

type Upstream struct {
	connections []*UpstreamConnection
	cache       *cache.Cache
}

type UpstreamConfig struct {
	Ip       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
}

func NewUpstream(config []UpstreamConfig) *Upstream {
	u := &Upstream{}

	u.cache = cache.New(time.Second*time.Duration(defaultCacheTtl), time.Second*time.Duration(defaultCacheTtl)*10)
	for _, upstreamConfig := range config {
		client := &dns.Client{
			Net:     upstreamConfig.Protocol,
			Timeout: time.Duration(upstreamConfig.Timeout) * time.Millisecond,
		}
		connectionStr := upstreamConfig.Ip + ":" + strconv.Itoa(upstreamConfig.Port)
		connection := &UpstreamConnection{
			client:        client,
			connectionStr: connectionStr,
		}
		u.connections = append(u.connections, connection)
	}

	return u
}

func (u *Upstream) Query(location string, qtype uint16) ([]dns.RR, int) {
	key := location + ":" + strconv.Itoa(int(qtype))
	res, exp, found := u.cache.GetWithExpiration(key)
	if found {
		records := res.([]dns.RR)
		for _, record := range records {
			record.Header().Ttl = uint32(time.Until(exp).Seconds())
		}
		return records, dns.RcodeSuccess
	}
	m := new(dns.Msg)
	m.SetQuestion(location, qtype)
	for _, c := range u.connections {
		r, _, err := c.client.Exchange(m, c.connectionStr)
		if err != nil {
			logger.Default.Errorf("failed to retrieve record %s from upstream %s : %s", location, c.connectionStr, err)
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			logger.Default.Errorf("upstream error response : %s for %s", dns.RcodeToString[r.Rcode], location)
		}
		if len(r.Answer) == 0 {
			return []dns.RR{}, dns.RcodeNameError
		}
		minTtl := r.Answer[0].Header().Ttl
		for _, record := range r.Answer {
			if record.Header().Ttl < minTtl {
				minTtl = record.Header().Ttl
			}
		}
		u.cache.Set(key, r.Answer, time.Duration(minTtl)*time.Second)
		u.connections[0], c = c, u.connections[0]

		return r.Answer, dns.RcodeSuccess
	}
	return []dns.RR{}, dns.RcodeServerFailure
}

const (
	defaultCacheTtl = 600
)
