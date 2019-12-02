package handler

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/hawell/logger"
	"github.com/miekg/dns"
)

var (
	NSecTypes = []uint16{dns.TypeRRSIG, dns.TypeNSEC}
)

type rrset struct {
	qname string
	qtype uint16
}

func splitSets(rrs []dns.RR) map[rrset][]dns.RR {
	m := make(map[rrset][]dns.RR)

	for _, r := range rrs {
		if r.Header().Rrtype == dns.TypeRRSIG || r.Header().Rrtype == dns.TypeOPT {
			continue
		}

		if s, ok := m[rrset{r.Header().Name, r.Header().Rrtype}]; ok {
			s = append(s, r)
			m[rrset{r.Header().Name, r.Header().Rrtype}] = s
			continue
		}

		s := make([]dns.RR, 1, 3)
		s[0] = r
		m[rrset{r.Header().Name, r.Header().Rrtype}] = s
	}

	if len(m) > 0 {
		return m
	}
	return nil
}

func Sign(rrs []dns.RR, qname string, z *Zone) []dns.RR {
	var res []dns.RR
	sets := splitSets(rrs)
	for _, set := range sets {
		res = append(res, set...)
		switch set[0].Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeOPT:
			continue
		case dns.TypeDNSKEY:
			res = append(res, z.DnsKeySig)
		default:
			if rrsig, err := sign(set, qname, z.ZSK, set[0].Header().Ttl); err == nil {
				res = append(res, rrsig)
			}
		}
	}
	return res
}

func sign(rrs []dns.RR, name string, key *ZoneKey, ttl uint32) (*dns.RRSIG, error) {
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl},
		Inception:  key.KeyInception,
		Expiration: key.KeyExpiration,
		KeyTag:     key.DnsKey.KeyTag(),
		SignerName: key.DnsKey.Hdr.Name,
		Algorithm:  key.DnsKey.Algorithm,
	}
	switch rrsig.Algorithm {
	case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		if err := rrsig.Sign(key.PrivateKey.(*rsa.PrivateKey), rrs); err != nil {
			logger.Default.Errorf("sign failed : %s", err)
			return nil, err
		}
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		if err := rrsig.Sign(key.PrivateKey.(*ecdsa.PrivateKey), rrs); err != nil {
			logger.Default.Errorf("sign failed : %s", err)
			return nil, err
		}
	case dns.DSA, dns.DSANSEC3SHA1:
		//rrsig.Sign(zone.PrivateKey.(*dsa.PrivateKey), rrs)
		fallthrough
	default:
		return nil, errors.New("invalid or not supported algorithm")
	}
	return rrsig, nil
}

func NSec(name string, zone *Zone) dns.RR {
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: zone.Config.SOA.MinTtl},
		NextDomain: "\\000." + name,
		TypeBitMap: NSecTypes,
	}

	return nsec
}
