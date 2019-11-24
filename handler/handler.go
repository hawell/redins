package handler

import (
	"arvancloud/redins/handler/logformat"
	"github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-immutable-radix"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

type DnsRequestHandler struct {
	Config         *HandlerConfig
	Zones          *iradix.Tree
	LastZoneUpdate time.Time
	Redis          *uperdis.Redis
	Logger         *logger.EventLogger
	RecordCache    *cache.Cache
	ZoneCache      *cache.Cache
	geoip          *GeoIp
	healthcheck    *Healthcheck
	upstream       *Upstream
	quit           chan struct{}
	quitWG         sync.WaitGroup
	logQueue       chan map[string]interface{}
}

type HandlerConfig struct {
	Upstream          []UpstreamConfig    `json:"upstream,omitempty"`
	GeoIp             GeoIpConfig         `json:"geoip,omitempty"`
	HealthCheck       HealthcheckConfig   `json:"healthcheck,omitempty"`
	MaxTtl            int                 `json:"max_ttl,omitempty"`
	CacheTimeout      int                 `json:"cache_timeout,omitempty"`
	ZoneReload        int                 `json:"zone_reload,omitempty"`
	LogSourceLocation bool                `json:"log_source_location,omitempty"`
	UpstreamFallback  bool                `json:"upstream_fallback,omitempty"`
	Redis             uperdis.RedisConfig `json:"redis,omitempty"`
	Log               logger.LogConfig    `json:"log,omitempty"`
}

func NewHandler(config *HandlerConfig) *DnsRequestHandler {
	h := &DnsRequestHandler{
		Config: config,
	}

	getFormatter := func(name string) logrus.Formatter {
		switch name {
		case "capnp_request":
			return &logformat.CapnpRequestLogFormatter{}
		case "json":
			return &logrus.JSONFormatter{TimestampFormat: h.Config.Log.TimeFormat}
		case "text":
			return &logrus.TextFormatter{TimestampFormat: h.Config.Log.TimeFormat}
		default:
			return &logrus.TextFormatter{TimestampFormat: h.Config.Log.TimeFormat}
		}
	}

	h.logQueue = make(chan map[string]interface{}, 1000)
	go func() {
		h.quitWG.Add(1)
		for {
			select {
			case <-h.quit:
				h.quitWG.Done()
				return
			case data := <-h.logQueue:
				h.Logger.Log(data, "dns request")
			}
		}
	}()
	h.Redis = uperdis.NewRedis(&config.Redis)
	h.Logger = logger.NewLogger(&config.Log, getFormatter)
	h.geoip = NewGeoIp(&config.GeoIp)
	h.healthcheck = NewHealthcheck(&config.HealthCheck, h.Redis)
	h.upstream = NewUpstream(config.Upstream)
	h.Zones = iradix.New()
	h.quit = make(chan struct{})

	h.LoadZones()

	h.RecordCache = cache.New(time.Second*time.Duration(h.Config.CacheTimeout), time.Duration(h.Config.CacheTimeout)*time.Second*10)
	h.ZoneCache = cache.New(time.Second*time.Duration(h.Config.CacheTimeout), time.Duration(h.Config.CacheTimeout)*time.Second*10)

	go h.healthcheck.Start()

	if h.Redis.SubscribeEvent("redins:zones", func(channel string, event string) {
		logger.Default.Debug("loading zones")
		h.LoadZones()
	}) != nil {
		logger.Default.Warning("event notification is not available, adding/removing zones will not be instant")
		go func() {
			logger.Default.Debug("zone updater")
			h.quitWG.Add(1)
			ticker := time.NewTicker(time.Duration(h.Config.ZoneReload) * time.Second)
			for {
				select {
				case <-h.quit:
					ticker.Stop()
					logger.Default.Debug("zone updater stopped")
					h.quitWG.Done()
					return
				case <-ticker.C:
					logger.Default.Debugf("%v", h.Zones)
					logger.Default.Debug("loading zones")
					h.LoadZones()
				}
			}
		}()
	}

	return h
}

func (h *DnsRequestHandler) ShutDown() {
	logger.Default.Debug("handler : stopping")
	h.healthcheck.ShutDown()
	close(h.logQueue)
	close(h.quit)
	h.quitWG.Wait()
	logger.Default.Debug("handler : stopped")
}

func (h *DnsRequestHandler) HandleRequest(context *RequestContext) {
	// TODO: refactor handle flow
	qname := context.Name()
	qtype := context.QType()

	logger.Default.Debugf("name : %s", context.Name())
	logger.Default.Debugf("type : %s", context.Type())

	if h.Config.LogSourceLocation {
		sourceIP := context.SourceIp()
		_, _, sourceCountry, _ := h.geoip.GetGeoLocation(sourceIP)
		context.LogData["source_country"] = sourceCountry
		sourceASN, _ := h.geoip.GetASN(sourceIP)
		context.LogData["source_asn"] = sourceASN
	}

	auth := true

	var record *Record
	var localRes int
	var res int
	var answers []dns.RR
	var authority []dns.RR
	var additional []dns.RR
	record, localRes = h.FetchRecord(qname)
	originalRecord := record
	if record != nil {
		context.LogData["domain_uuid"] = record.Zone.Config.DomainId
		if qtype != dns.TypeCNAME {
			count := 0
			for {
				if count >= 10 {
					answers = []dns.RR{}
					localRes = dns.RcodeServerFailure
					logger.Default.Errorf("CNAME loop in request %s->%s", context.Name(), context.Type())
					break
				}
				if localRes != dns.RcodeSuccess {
					break
				}
				if record.CNAME == nil {
					break
				}
				if !record.Zone.Config.CnameFlattening {
					answers = append(answers, h.CNAME(qname, record)...)
					if h.Matches(record.CNAME.Host) != originalRecord.Zone.Name {
						break
					}
					qname = record.CNAME.Host
				}
				record, localRes = h.FetchRecord(record.CNAME.Host)
				count++
			}
		}
	} else {
		context.LogData["domain_uuid"] = ""
	}

	res = localRes
	if localRes == dns.RcodeSuccess {
		if qname != originalRecord.Zone.Name && len(record.NS.Data) > 0 {
			authority = append(authority, h.NS(qname, record)...)
			for _, ns := range record.NS.Data {
				glueAddress, glueRes := h.FetchRecord(ns.Host)
				if glueRes == dns.RcodeSuccess {
					additional = append(additional, h.A(ns.Host, glueAddress, glueAddress.A.Data)...)
				}
			}
			auth = false
			res = dns.RcodeNotAuth
		} else {
			switch qtype {
			case dns.TypeA:
				if len(record.A.Data) == 0 {
					if record.ANAME != nil {
						// TODO: handle aname chain
						anameAnswer, anameRes := h.FetchRecord(record.ANAME.Location)
						if anameRes == dns.RcodeSuccess {
							ips := h.Filter(context, &anameAnswer.A)
							answers = append(answers, h.A(qname, anameAnswer, ips)...)
						} else if anameRes == dns.RcodeNotAuth {
							upstreamAnswers, upstreamRes := h.upstream.Query(record.ANAME.Location, dns.TypeA)
							if upstreamRes == dns.RcodeSuccess {
								var anameRecord []dns.RR
								for _, r := range upstreamAnswers {
									if r.Header().Name == record.ANAME.Location && r.Header().Rrtype == dns.TypeA {
										a := r.(*dns.A)
										anameRecord = append(anameRecord, &dns.A{A: a.A, Hdr: dns.RR_Header{Rrtype: dns.TypeA, Name: qname, Ttl: a.Hdr.Ttl, Class: dns.ClassINET, Rdlength: 0}})
									}
								}
								answers = append(answers, anameRecord...)
							}
							res = upstreamRes
						} else {
							res = anameRes
						}
					}
				} else {
					ips := h.Filter(context, &record.A)
					answers = append(answers, h.A(qname, record, ips)...)
				}
			case dns.TypeAAAA:
				if len(record.AAAA.Data) == 0 {
					if record.ANAME != nil {
						anameAnswer, anameRes := h.FetchRecord(record.ANAME.Location)
						if anameRes == dns.RcodeSuccess {
							ips := h.Filter(context, &anameAnswer.AAAA)
							answers = append(answers, h.AAAA(qname, anameAnswer, ips)...)
						} else if anameRes == dns.RcodeNotAuth {
							upstreamAnswers, upstreamRes := h.upstream.Query(record.ANAME.Location, dns.TypeAAAA)
							if upstreamRes == dns.RcodeSuccess {
								var anameRecord []dns.RR
								for _, r := range upstreamAnswers {
									if r.Header().Name == record.ANAME.Location && r.Header().Rrtype == dns.TypeAAAA {
										a := r.(*dns.AAAA)
										anameRecord = append(anameRecord, &dns.AAAA{AAAA: a.AAAA, Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA, Name: qname, Ttl: a.Hdr.Ttl, Class: dns.ClassINET, Rdlength: 0}})
									}
								}
								answers = append(answers, anameRecord...)
							}
							res = upstreamRes
						} else {
							res = anameRes
						}
					}
				} else {
					ips := h.Filter(context, &record.AAAA)
					answers = append(answers, h.AAAA(qname, record, ips)...)
				}
			case dns.TypeCNAME:
				answers = append(answers, h.CNAME(qname, record)...)
			case dns.TypeTXT:
				answers = append(answers, h.TXT(qname, record)...)
			case dns.TypeNS:
				answers = append(answers, h.NS(qname, record)...)
			case dns.TypeMX:
				answers = append(answers, h.MX(qname, record)...)
			case dns.TypeSRV:
				answers = append(answers, h.SRV(qname, record)...)
			case dns.TypeCAA:
				caaRecord := h.FindCAA(record)
				if caaRecord != nil {
					answers = append(answers, h.CAA(qname, caaRecord)...)
				}
			case dns.TypePTR:
				answers = append(answers, h.PTR(qname, record)...)
			case dns.TypeTLSA:
				answers = append(answers, h.TLSA(qname, record)...)
			case dns.TypeSOA:
				answers = append(answers, record.Zone.Config.SOA.Data)
			case dns.TypeDNSKEY:
				if record.Zone.Config.DnsSec {
					answers = []dns.RR{record.Zone.ZSK.DnsKey, record.Zone.KSK.DnsKey}
				}
			default:
				answers = []dns.RR{}
				authority = []dns.RR{}
				res = dns.RcodeNotImplemented
			}
			if len(answers) == 0 {
				if originalRecord.CNAME != nil {
					answers = append(answers, h.CNAME(qname, record)...)
				} else {
					authority = append(authority, originalRecord.Zone.Config.SOA.Data)
				}
			}
		}
	} else if localRes == dns.RcodeNameError {
		answers = []dns.RR{}
		authority = append(authority, originalRecord.Zone.Config.SOA.Data)
	} else if localRes == dns.RcodeNotAuth {
		// TODO: remove upstream fallback
		if h.Config.UpstreamFallback {
			upstreamAnswers, upstreamRes := h.upstream.Query(dns.Fqdn(qname), qtype)
			if upstreamRes == dns.RcodeSuccess {
				answers = append(answers, upstreamAnswers...)
				auth = false
			}
			res = upstreamRes
		} else if originalRecord != nil && originalRecord.CNAME != nil {
			if len(answers) == 0 {
				answers = append(answers, h.CNAME(qname, originalRecord)...)
			}
			res = dns.RcodeSuccess
		}
	}

	if auth && context.Do() && originalRecord != nil && originalRecord.Zone.Config.DnsSec {
		switch res {
		case dns.RcodeSuccess:
			if len(answers) == 0 {
				authority = append(authority, NSec(qname, originalRecord.Zone))
			}
		case dns.RcodeNameError:
			authority = append(authority, NSec(qname, originalRecord.Zone))
			res = dns.RcodeSuccess
		}
		answers = Sign(answers, qname, originalRecord)
		authority = Sign(authority, qname, originalRecord)
	}

	h.LogRequest(context, res)
	m := new(dns.Msg)
	m.SetReply(context.Req)
	m.Authoritative, m.RecursionAvailable, m.Compress = auth, h.Config.UpstreamFallback, true
	m.SetRcode(context.Req, res)
	m.Answer = append(m.Answer, answers...)
	m.Ns = append(m.Ns, authority...)
	m.Extra = append(m.Extra, additional...)

	context.SizeAndDo(m)
	m = context.Scrub(m)
	if err := context.W.WriteMsg(m); err != nil {
		logger.Default.Error("write error : ", err, " msg : ", m.String())
		_ = context.W.Close()
	}
}

func (h *DnsRequestHandler) Filter(state *RequestContext, rrset *IP_RRSet) []IP_RR {
	ips := h.healthcheck.FilterHealthcheck(state.Name(), rrset)
	switch rrset.FilterConfig.GeoFilter {
	case "asn":
		ips = h.geoip.GetSameASN(state.SourceIp(), ips)
	case "country":
		ips = h.geoip.GetSameCountry(state.SourceIp(), ips)
	case "asn+country":
		ips = h.geoip.GetSameASN(state.SourceIp(), ips)
		ips = h.geoip.GetSameCountry(state.SourceIp(), ips)
	case "location":
		ips = h.geoip.GetMinimumDistance(state.SourceIp(), ips)
	default:
	}
	if len(ips) <= 1 {
		return ips
	}

	switch rrset.FilterConfig.Count {
	case "single":
		index := 0
		switch rrset.FilterConfig.Order {
		case "weighted":
			index = ChooseIp(ips, true)
		case "rr":
			index = ChooseIp(ips, false)
		default:
			index = 0
		}
		return []IP_RR{ips[index]}

	case "multi":
		fallthrough
	default:
		index := 0
		switch rrset.FilterConfig.Order {
		case "weighted":
			index = ChooseIp(ips, true)
		case "rr":
			index = ChooseIp(ips, false)
		default:
			index = 0
		}
		return append(ips[index:], ips[:index]...)
	}
}

func (h *DnsRequestHandler) LogRequest(state *RequestContext, responseCode int) {
	state.LogData["process_time"] = time.Since(state.StartTime).Nanoseconds() / 1000000
	state.LogData["response_code"] = responseCode
	state.LogData["log_type"] = "request"
	select {
	case h.logQueue <- state.LogData:
	default:
		logger.Default.Warning("log queue is full")
	}
}

func reverseZone(zone string) string {
	x := strings.Split(zone, ".")
	var y string
	for i := len(x) - 1; i >= 0; i-- {
		y += x[i] + "."
	}
	return y
}

func (h *DnsRequestHandler) LoadZones() {
	h.LastZoneUpdate = time.Now()
	zones, err := h.Redis.SMembers("redins:zones")
	if err != nil {
		logger.Default.Error("cannot load zones : ", err)
	}
	newZones := iradix.New()
	for _, zone := range zones {
		newZones, _, _ = newZones.Insert([]byte(reverseZone(zone)), zone)
	}
	h.Zones = newZones
}

func (h *DnsRequestHandler) FetchRecord(qname string) (*Record, int) {
	cachedRecord, found := h.RecordCache.Get(qname)
	if found {
		logger.Default.Debug("cached")
		return cachedRecord.(*Record), dns.RcodeSuccess
	} else {
		record, res := h.GetRecord(qname)
		if res == dns.RcodeSuccess {
			h.RecordCache.Set(qname, record, time.Duration(h.Config.CacheTimeout)*time.Second)
		}
		return record, res
	}
}

func (h *DnsRequestHandler) A(name string, record *Record, ips []IP_RR) (answers []dns.RR) {
	for _, ip := range ips {
		if ip.Ip == nil {
			continue
		}
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: h.getTtl(record.A.Ttl)}
		r.A = ip.Ip
		answers = append(answers, r)
	}
	return
}

func (h *DnsRequestHandler) AAAA(name string, record *Record, ips []IP_RR) (answers []dns.RR) {
	for _, ip := range ips {
		if ip.Ip == nil {
			continue
		}
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA,
			Class: dns.ClassINET, Ttl: h.getTtl(record.AAAA.Ttl)}
		r.AAAA = ip.Ip
		answers = append(answers, r)
	}
	return
}

func (h *DnsRequestHandler) CNAME(name string, record *Record) (answers []dns.RR) {
	if record.CNAME == nil {
		return
	}
	r := new(dns.CNAME)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME,
		Class: dns.ClassINET, Ttl: h.getTtl(record.CNAME.Ttl)}
	r.Target = dns.Fqdn(record.CNAME.Host)
	answers = append(answers, r)
	return
}

func (h *DnsRequestHandler) TXT(name string, record *Record) (answers []dns.RR) {
	for _, txt := range record.TXT.Data {
		if len(txt.Text) == 0 {
			continue
		}
		r := new(dns.TXT)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: h.getTtl(record.TXT.Ttl)}
		r.Txt = split255(txt.Text)
		answers = append(answers, r)
	}
	return
}

func (h *DnsRequestHandler) NS(name string, record *Record) (answers []dns.RR) {
	for _, ns := range record.NS.Data {
		if len(ns.Host) == 0 {
			continue
		}
		r := new(dns.NS)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeNS,
			Class: dns.ClassINET, Ttl: h.getTtl(record.NS.Ttl)}
		r.Ns = ns.Host
		answers = append(answers, r)
	}
	return
}

func (h *DnsRequestHandler) MX(name string, record *Record) (answers []dns.RR) {
	for _, mx := range record.MX.Data {
		if len(mx.Host) == 0 {
			continue
		}
		r := new(dns.MX)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeMX,
			Class: dns.ClassINET, Ttl: h.getTtl(record.MX.Ttl)}
		r.Mx = mx.Host
		r.Preference = mx.Preference
		answers = append(answers, r)
	}
	return
}

func (h *DnsRequestHandler) SRV(name string, record *Record) (answers []dns.RR) {
	for _, srv := range record.SRV.Data {
		if len(srv.Target) == 0 {
			continue
		}
		r := new(dns.SRV)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeSRV,
			Class: dns.ClassINET, Ttl: h.getTtl(record.SRV.Ttl)}
		r.Target = srv.Target
		r.Weight = srv.Weight
		r.Port = srv.Port
		r.Priority = srv.Priority
		answers = append(answers, r)
	}
	return
}

func (h *DnsRequestHandler) CAA(name string, record *Record) (answers []dns.RR) {
	for _, caa := range record.CAA.Data {
		r := new(dns.CAA)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeCAA,
			Class: dns.ClassINET, Ttl: h.getTtl(record.CAA.Ttl)}
		r.Value = caa.Value
		r.Flag = caa.Flag
		r.Tag = caa.Tag
		answers = append(answers, r)
	}
	return
}

func (h *DnsRequestHandler) PTR(name string, record *Record) (answers []dns.RR) {
	if record.PTR == nil {
		return
	}
	r := new(dns.PTR)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypePTR,
		Class: dns.ClassINET, Ttl: h.getTtl(record.PTR.Ttl)}
	r.Ptr = dns.Fqdn(record.PTR.Domain)
	answers = append(answers, r)
	return
}

func (h *DnsRequestHandler) TLSA(name string, record *Record) (answers []dns.RR) {
	for _, tlsa := range record.TLSA.Data {
		r := new(dns.TLSA)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeTLSA,
			Class: dns.ClassNONE, Ttl: h.getTtl(record.TLSA.Ttl)}
		r.Usage = tlsa.Usage
		r.Selector = tlsa.Selector
		r.MatchingType = tlsa.MatchingType
		r.Certificate = tlsa.Certificate
		answers = append(answers, r)
	}
	return
}

func (h *DnsRequestHandler) getTtl(ttl uint32) uint32 {
	maxTtl := uint32(h.Config.MaxTtl)
	if ttl == 0 {
		return maxTtl
	}
	if maxTtl == 0 {
		return ttl
	}
	if ttl > maxTtl {
		return maxTtl
	}
	return ttl
}

func split255(s string) []string {
	if len(s) < 255 {
		return []string{s}
	}
	var sx []string
	p, i := 0, 255
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+255, i+255
	}

	return sx
}

func (h *DnsRequestHandler) Matches(qname string) string {
	rname := reverseZone(qname)
	if _, zname, ok := h.Zones.Root().LongestPrefix([]byte(rname)); ok {
		return zname.(string)
	}
	return ""
}

func (h *DnsRequestHandler) GetRecord(qname string) (record *Record, rcode int) {
	logger.Default.Debug("GetRecord")

	zone := h.Matches(qname)
	logger.Default.Debugf("zone : %s", zone)
	if zone == "" {
		logger.Default.Debugf("no matching zone found for %s", qname)
		return nil, dns.RcodeNotAuth
	}

	z := h.LoadZone(zone)
	if z == nil {
		logger.Default.Errorf("empty zone : %s", zone)
		return nil, dns.RcodeServerFailure
	}

	location := z.findLocation(qname)
	if len(location) == 0 { // empty, no results
		return &Record{Name: qname, Zone: z}, dns.RcodeNameError
	}
	logger.Default.Debugf("location : %s", location)

	record = h.LoadLocation(location, z)
	if record == nil {
		return nil, dns.RcodeServerFailure
	}

	return record, dns.RcodeSuccess
}

func (h *DnsRequestHandler) loadKey(pub string, priv string) *ZoneKey {
	pubStr, _ := h.Redis.Get(pub)
	if pubStr == "" {
		logger.Default.Errorf("key is not set : %s", pub)
		return nil
	}
	privStr, _ := h.Redis.Get(priv)
	if privStr == "" {
		logger.Default.Errorf("key is not set : %s", priv)
		return nil
	}
	privStr = strings.Replace(privStr, "\\n", "\n", -1)
	zoneKey := new(ZoneKey)
	if rr, err := dns.NewRR(pubStr); err == nil {
		zoneKey.DnsKey = rr.(*dns.DNSKEY)
	} else {
		logger.Default.Errorf("cannot parse zone key : %s", err)
		return nil
	}
	if pk, err := zoneKey.DnsKey.NewPrivateKey(privStr); err == nil {
		zoneKey.PrivateKey = pk
	} else {
		logger.Default.Errorf("cannot create private key : %s", err)
		return nil
	}
	now := time.Now()
	zoneKey.KeyInception = uint32(now.Add(-3 * time.Hour).Unix())
	zoneKey.KeyExpiration = uint32(now.Add(8 * 24 * time.Hour).Unix())
	return zoneKey
}

func (h *DnsRequestHandler) LoadZone(zone string) *Zone {
	cachedZone, found := h.ZoneCache.Get(zone)
	if found {
		return cachedZone.(*Zone)
	}

	locations, err := h.Redis.GetHKeys("redins:zones:" + zone)
	if err != nil {
		logger.Default.Errorf("cannot load zone %s locations : %s", zone, err)
	}
	config, err := h.Redis.Get("redins:zones:" + zone + ":config")
	if err != nil {
		logger.Default.Errorf("cannot load zone %s config : %s", zone, err)
	}

	z := NewZone(zone, locations, config)
	h.LoadZoneKeys(z)

	h.ZoneCache.Set(zone, z, time.Duration(h.Config.CacheTimeout)*time.Second)
	return z
}

func (h *DnsRequestHandler) LoadZoneKeys(z *Zone) {
	if z.Config.DnsSec {
		z.ZSK = h.loadKey("redins:zones:"+z.Name+":zsk:pub", "redins:zones:"+z.Name+":zsk:priv")
		if z.ZSK == nil {
			z.Config.DnsSec = false
			return
		}
		z.KSK = h.loadKey("redins:zones:"+z.Name+":ksk:pub", "redins:zones:"+z.Name+":ksk:priv")
		if z.KSK == nil {
			z.Config.DnsSec = false
			return
		}

		z.ZSK.DnsKey.Flags = 256
		z.KSK.DnsKey.Flags = 257
		if z.ZSK.DnsKey.Hdr.Ttl != z.KSK.DnsKey.Hdr.Ttl {
			z.ZSK.DnsKey.Hdr.Ttl = z.KSK.DnsKey.Hdr.Ttl
		}

		if rrsig, err := sign([]dns.RR{z.ZSK.DnsKey, z.KSK.DnsKey}, z.Name, z.KSK, z.KSK.DnsKey.Hdr.Ttl); err == nil {
			z.DnsKeySig = rrsig
		} else {
			logger.Default.Errorf("cannot create RRSIG for DNSKEY : %s", err)
			z.Config.DnsSec = false
			return
		}
	}
}

func (h *DnsRequestHandler) LoadLocation(location string, z *Zone) *Record {
	var label, name string
	if location == z.Name {
		name = z.Name
		label = "@"
	} else {
		name = location + "." + z.Name
		label = location
	}
	r := new(Record)
	r.A = IP_RRSet{
		FilterConfig: IpFilterConfig{
			Count:     "multi",
			Order:     "none",
			GeoFilter: "none",
		},
		HealthCheckConfig: IpHealthCheckConfig{
			Enable: false,
		},
	}
	r.AAAA = r.A
	r.Zone = z
	r.Name = name

	val, _ := h.Redis.HGet("redins:zones:"+z.Name, label)
	if val == "" {
		return r
	}
	err := jsoniter.Unmarshal([]byte(val), r)
	if err != nil {
		logger.Default.Errorf("cannot parse json : zone -> %s, location -> %s, \"%s\" -> %s", z.Name, location, val, err)
		return nil
	}

	return r
}

func (h *DnsRequestHandler) SetLocation(location string, z *Zone, val *Record) {
	jsonValue, err := jsoniter.Marshal(val)
	if err != nil {
		logger.Default.Errorf("cannot encode to json : %s", err)
		return
	}
	var label string
	if location == z.Name {
		label = "@"
	} else {
		label = location
	}
	if err = h.Redis.HSet(z.Name, label, string(jsonValue)); err != nil {
		logger.Default.Error("redis error : ", err)
	}
}

func ChooseIp(ips []IP_RR, weighted bool) int {
	sum := 0

	if !weighted {
		return rand.Intn(len(ips))
	}

	for _, ip := range ips {
		sum += ip.Weight
	}
	index := 0

	// all Ips have 0 weight, choosing a random one
	if sum == 0 {
		return rand.Intn(len(ips))
	}

	x := rand.Intn(sum)
	for ; index < len(ips); index++ {
		// skip Ips with 0 weight
		x -= ips[index].Weight
		if x < 0 {
			break
		}
	}
	if index >= len(ips) {
		index--
	}

	return index
}

func (h *DnsRequestHandler) FindCAA(record *Record) *Record {
	zone := record.Zone
	currentRecord := record
	for currentRecord != nil && strings.HasSuffix(currentRecord.Name, zone.Name) {
		if len(currentRecord.CAA.Data) != 0 {
			return currentRecord
		}
		splits := strings.SplitAfterN(currentRecord.Name, ".", 2)
		if len(splits) != 2 {
			return nil
		}
		currentRecord, _ = h.FetchRecord(splits[1])
	}
	return nil
}
