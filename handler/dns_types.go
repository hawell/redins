package handler

import (
	"crypto"
	"encoding/json"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"net"
)

type RRSets struct {
	A     IP_RRSet      `json:"a,omitempty"`
	AAAA  IP_RRSet      `json:"aaaa,omitempty"`
	TXT   TXT_RRSet     `json:"txt,omitempty"`
	CNAME *CNAME_RRSet  `json:"cname,omitempty"`
	NS    NS_RRSet      `json:"ns,omitempty"`
	MX    MX_RRSet      `json:"mx,omitempty"`
	SRV   SRV_RRSet     `json:"srv,omitempty"`
	CAA   CAA_RRSet     `json:"caa,omitempty"`
	PTR   *PTR_RRSet    `json:"ptr,omitempty"`
	TLSA  TLSA_RRSet    `json:"tlsa,omitempty"`
	ANAME *ANAME_Record `json:"aname,omitempty"`
}

type Record struct {
	RRSets
	Zone *Zone  `json:"-"`
	Name string `json:"-"`
}

type ZoneKey struct {
	DnsKey        *dns.DNSKEY
	PrivateKey    crypto.PrivateKey
	KeyInception  uint32
	KeyExpiration uint32
}

type ZoneConfig struct {
	DomainId        string     `json:"domain_id,omitempty"`
	SOA             *SOA_RRSet `json:"soa,omitempty"`
	DnsSec          bool       `json:"dnssec,omitempty"`
	CnameFlattening bool       `json:"cname_flattening,omitempty"`
}

type Zone struct {
	Name      string
	Config    ZoneConfig
	Locations map[string]struct{}
	ZSK       *ZoneKey
	KSK       *ZoneKey
	DnsKeySig dns.RR
}

type IP_RRSet struct {
	FilterConfig      IpFilterConfig      `json:"filter,omitempty"`
	HealthCheckConfig IpHealthCheckConfig `json:"health_check,omitempty"`
	Ttl               uint32              `json:"ttl,omitempty"`
	Data              []IP_RR             `json:"records,omitempty"`
}

type IP_RR struct {
	Weight  int      `json:"weight,omitempty"`
	Ip      net.IP   `json:"ip"`
	Country []string `json:"country,omitempty"`
	ASN     []uint   `json:"asn,omitempty"`
}

type _IP_RR struct {
	Country interface{} `json:"country,omitempty"`
	ASN     interface{} `json:"asn,omitempty"`
	Weight  int         `json:"weight,omitempty"`
	Ip      net.IP      `json:"ip"`
}

func (iprr *IP_RR) UnmarshalJSON(data []byte) error {
	var _ip_rr _IP_RR
	if err := json.Unmarshal(data, &_ip_rr); err != nil {
		return err
	}

	iprr.Ip = _ip_rr.Ip
	iprr.Weight = _ip_rr.Weight

	switch v := _ip_rr.Country.(type) {
	case nil:
	case string:
		iprr.Country = []string{v}
	case []interface{}:
		for _, x := range v {
			switch x.(type) {
			case string:
				iprr.Country = append(iprr.Country, x.(string))
			default:
				return errors.Errorf("string expected got %T:%v", x, x)
			}
		}
	default:
		return errors.Errorf("cannot parse country value: %v type: %T", v, v)
	}
	switch v := _ip_rr.ASN.(type) {
	case nil:
	case float64:
		iprr.ASN = []uint{uint(v)}
	case []interface{}:
		for _, x := range v {
			switch x.(type) {
			case float64:
				iprr.ASN = append(iprr.ASN, uint(x.(float64)))
			default:
				return errors.Errorf("invalid type:%T:%v", x, x)
			}

		}
	default:
		return errors.Errorf("cannot parse asn value: %v type: %T", v, v)
	}
	return nil
}

type IpHealthCheckConfig struct {
	Protocol  string `json:"protocol,omitempty"`
	Uri       string `json:"uri,omitempty"`
	Port      int    `json:"port,omitempty"`
	Timeout   int    `json:"timeout,omitempty"`
	UpCount   int    `json:"up_count,omitempty"`
	DownCount int    `json:"down_count,omitempty"`
	Enable    bool   `json:"enable,omitempty"`
}

type IpFilterConfig struct {
	Count     string `json:"count,omitempty"`      // "multi", "single"
	Order     string `json:"order,omitmpty"`       // "weighted", "rr", "none"
	GeoFilter string `json:"geo_filter,omitempty"` // "country", "location", "asn", "asn+country", "none"
}

type CNAME_RRSet struct {
	Host string `json:"host"`
	Ttl  uint32 `json:"ttl,omitempty"`
}

type TXT_RRSet struct {
	Ttl  uint32   `json:"ttl,omitempty"`
	Data []TXT_RR `json:"records,omitempty"`
}

type TXT_RR struct {
	Text string `json:"text"`
}

type NS_RRSet struct {
	Ttl  uint32  `json:"ttl,omitempty"`
	Data []NS_RR `json:"records,omitempty"`
}

type NS_RR struct {
	Host string `json:"host"`
}

type MX_RRSet struct {
	Ttl  uint32  `json:"ttl,omitempty"`
	Data []MX_RR `json:"records,omitempty"`
}

type MX_RR struct {
	Host       string `json:"host"`
	Preference uint16 `json:"preference"`
}

type SRV_RRSet struct {
	Ttl  uint32   `json:"ttl,omitempty"`
	Data []SRV_RR `json:"records,omitempty"`
}

type SRV_RR struct {
	Target   string `json:"target"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
}

type CAA_RRSet struct {
	Ttl  uint32   `json:"ttl,omitempty"`
	Data []CAA_RR `json:"records,omitempty"`
}

type CAA_RR struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
	Flag  uint8  `json:"flag"`
}

type PTR_RRSet struct {
	Domain string `json:"domain"`
	Ttl    uint32 `json:"ttl,omitempty"`
}

type TLSA_RRSet struct {
	Ttl  uint32    `json:"ttl,omitempty"`
	Data []TLSA_RR `json:"records,omitempty"`
}

type TLSA_RR struct {
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Certificate  string `json:"certificate"`
}

type SOA_RRSet struct {
	Ns      string   `json:"ns"`
	MBox    string   `json:"MBox"`
	Data    *dns.SOA `json:"-"`
	Ttl     uint32   `json:"ttl,omitempty"`
	Refresh uint32   `json:"refresh"`
	Retry   uint32   `json:"retry"`
	Expire  uint32   `json:"expire"`
	MinTtl  uint32   `json:"minttl"`
	Serial  uint32   `json:"serial"`
}

type ANAME_Record struct {
	Location string `json:"location,omitempty"`
}
