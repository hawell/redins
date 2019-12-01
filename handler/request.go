package handler

import (
	"github.com/coredns/coredns/request"
	"github.com/hawell/logger"
	"github.com/miekg/dns"
	"net"
	"time"
)

type RequestContext struct {
	request.Request
	StartTime  time.Time
	LogData    map[string]interface{}
	Auth       bool
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR

	SourceIp     net.IP
	SourceSubnet string
}

func NewRequestContext(w dns.ResponseWriter, r *dns.Msg) *RequestContext {
	context := &RequestContext{
		Request: request.Request{
			Req:  r,
			W:    w,
			Zone: "",
		},
		StartTime: time.Now(),
		Auth:      true,
	}
	context.SourceIp = context.sourceIp()
	context.SourceSubnet = context.sourceSubnet()
	context.LogData = map[string]interface{}{
		"source_ip":     context.SourceIp,
		"record":        context.Name(),
		"type":          context.Type(),
		"client_subnet": context.SourceSubnet,
		"domain_uuid":   "",

	}
	return context
}

func (context *RequestContext) sourceIp() net.IP {
	opt := context.Req.IsEdns0()
	if opt != nil && len(opt.Option) != 0 {
		for _, o := range opt.Option {
			switch v := o.(type) {
			case *dns.EDNS0_SUBNET:
				return v.Address
			}
		}
	}
	return net.ParseIP(context.IP())
}

func (context *RequestContext) sourceSubnet() string {
	opt := context.Req.IsEdns0()
	if opt != nil && len(opt.Option) != 0 {
		for _, o := range opt.Option {
			switch o.(type) {
			case *dns.EDNS0_SUBNET:
				return o.String()
			}
		}
	}
	return ""
}

func (context *RequestContext) Response(rcode int) {
	m := new(dns.Msg)
	m.Authoritative, m.RecursionAvailable, m.Compress = context.Auth, false, true
	m.SetRcode(context.Req, rcode)
	m.Answer = append(m.Answer, context.Answer...)
	m.Ns = append(m.Ns, context.Authority...)
	m.Extra = append(m.Extra, context.Additional...)

	context.SizeAndDo(m)
	m = context.Scrub(m)
	if err := context.W.WriteMsg(m); err != nil {
		logger.Default.Error("write error : ", err, " msg : ", m.String())
		_ = context.W.Close()
	}
}
