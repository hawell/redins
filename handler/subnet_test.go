package handler

import (
	"arvancloud/redins/test"
	"github.com/miekg/dns"
	"log"
	"net"
	"testing"
)

func TestSubnet(t *testing.T) {
	tc := test.Case{
		Qname: "example.com.", Qtype: dns.TypeA,
	}
	sa := "192.168.1.2"
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
	if r.IsEdns0() == nil {
		log.Printf("no edns\n")
		t.Fail()
	}
	w := test.NewRecorder(&test.ResponseWriter{})
	state := NewRequestContext(w, r)

	subnet := state.SourceSubnet
	if subnet != sa+"/32/0" {
		log.Printf("subnet = %s should be %s\n", subnet, sa)
		t.Fail()
	}
	address := state.SourceIp
	if address.String() != sa {
		log.Printf("address = %s should be %s\n", address.String(), sa)
		t.Fail()
	}
}
