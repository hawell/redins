package handler

import (
	"github.com/hawell/logger"
	jsoniter "github.com/json-iterator/go"
	"github.com/miekg/dns"
	"strings"
	"time"
)

type Zone struct {
	Name      string
	Config    ZoneConfig
	Locations map[string]struct{}
	ZSK       *ZoneKey
	KSK       *ZoneKey
	DnsKeySig dns.RR
}

type ZoneConfig struct {
	DomainId        string     `json:"domain_id,omitempty"`
	SOA             *SOA_RRSet `json:"soa,omitempty"`
	DnsSec          bool       `json:"dnssec,omitempty"`
	CnameFlattening bool       `json:"cname_flattening,omitempty"`
}

func NewZone(name string, locations []string, config string) *Zone {
	z := new(Zone)
	z.Name = name
	z.Locations = make(map[string]struct{})
	for _, val := range locations {
		z.Locations[val] = struct{}{}
	}

	z.Config = ZoneConfig{
		DnsSec:          false,
		CnameFlattening: false,
		SOA: &SOA_RRSet{
			Ns:      "ns1." + z.Name,
			MinTtl:  300,
			Refresh: 86400,
			Retry:   7200,
			Expire:  3600,
			MBox:    "hostmaster." + z.Name,
			Serial:  uint32(time.Now().Unix()),
			Ttl:     300,
		},
	}
	if len(config) > 0 {
		err := jsoniter.Unmarshal([]byte(config), &z.Config)
		if err != nil {
			logger.Default.Errorf("cannot parse zone config : %s", err)
		}
	}
	z.Config.SOA.Ns = dns.Fqdn(z.Config.SOA.Ns)
	z.Config.SOA.Data = &dns.SOA{
		Hdr:     dns.RR_Header{Name: z.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.Config.SOA.Ttl, Rdlength: 0},
		Ns:      z.Config.SOA.Ns,
		Mbox:    z.Config.SOA.MBox,
		Refresh: z.Config.SOA.Refresh,
		Retry:   z.Config.SOA.Retry,
		Expire:  z.Config.SOA.Expire,
		Minttl:  z.Config.SOA.MinTtl,
		Serial:  z.Config.SOA.Serial,
	}
	return z
}

const (
	ExactMatch = iota
	WildCardMatch
	NoMatch
)

func (z *Zone) FindLocation(query string) (string, int) {
	var (
		ok                bool
		closestEncloser   string
		sourceOfSynthesis string
	)

	// request for zone records
	if query == z.Name {
		return query, ExactMatch
	}

	query = strings.TrimSuffix(query, "."+z.Name)

	if _, ok = z.Locations[query]; ok {
		return query, ExactMatch
	}

	closestEncloser, sourceOfSynthesis, ok = splitQuery(query)
	for ok {
		ceExists := z.keyMatches(closestEncloser) || z.keyExists(closestEncloser)
		ssExists := z.keyExists(sourceOfSynthesis)
		if ceExists {
			if ssExists {
				return sourceOfSynthesis, WildCardMatch
			} else {
				return "", NoMatch
			}
		} else {
			closestEncloser, sourceOfSynthesis, ok = splitQuery(closestEncloser)
		}
	}
	return "", NoMatch
}

func (z *Zone) keyExists(key string) bool {
	_, ok := z.Locations[key]
	return ok
}

func (z *Zone) keyMatches(key string) bool {
	for value := range z.Locations {
		if strings.HasSuffix(value, key) {
			return true
		}
	}
	return false
}

func splitQuery(query string) (string, string, bool) {
	if query == "" {
		return "", "", false
	}
	var (
		splits            []string
		closestEncloser   string
		sourceOfSynthesis string
	)
	splits = strings.SplitAfterN(query, ".", 2)
	if len(splits) == 2 {
		closestEncloser = splits[1]
		sourceOfSynthesis = "*." + closestEncloser
	} else {
		closestEncloser = ""
		sourceOfSynthesis = "*"
	}
	return closestEncloser, sourceOfSynthesis, true
}
