package handler

import (
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"net"
	"time"
)

type RequestContext struct {
	request.Request
	StartTime time.Time
	LogData map[string]interface{}
}

func NewRequestContext(w dns.ResponseWriter, r *dns.Msg) *RequestContext {
	context := &RequestContext{
		Request: request.Request{
			Req:  r,
			W:    w,
			Zone: "",
		},
		StartTime: time.Now(),
	}
	context.LogData = map[string]interface{}{
		"source_ip": context.IP(),
		"record":    context.Name(),
		"type":      context.Type(),
		"client_subnet": context.SourceSubnet(),
	}
	return context
}

func (context *RequestContext) SourceIp() net.IP {
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

func (context *RequestContext) SourceSubnet() string {
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
