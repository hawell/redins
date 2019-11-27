package handler

import (
	"arvancloud/redins/handler/logformat"
	"github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"math/rand"
	"net"
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

func (h *DnsRequestHandler) Response(context *RequestContext, res int) {
	h.LogRequest(context, res)
	context.Response(res)
}

func (h *DnsRequestHandler) HandleRequest(context *RequestContext) {
	logger.Default.Debugf("[%d] start handle request - name : %s, type : %s", context.Req.Id, context.Name(), context.Type())
	if h.Config.LogSourceLocation {
		sourceIP := context.SourceIp
		_, _, sourceCountry, _ := h.geoip.GetGeoLocation(sourceIP)
		context.LogData["source_country"] = sourceCountry
		sourceASN, _ := h.geoip.GetASN(sourceIP)
		context.LogData["source_asn"] = sourceASN
	}

	zoneName := h.FindZone(context.Name())
	if zoneName == "" {
		context.LogData["domain_uuid"] = ""
		h.Response(context, dns.RcodeNotAuth)
		return
	}

	zone := h.LoadZone(zoneName)
	context.LogData["domain_uuid"] = zone.Config.DomainId

	loopCount := 0
	currentQName := context.Name()
	currentRecord := &Record{}
	res := dns.RcodeSuccess
loop:
	for {
		if loopCount > 10 {
			logger.Default.Errorf("CNAME loop in request %s->%s", context.Name(), context.Type())
			context.Answer = []dns.RR{}
			res = dns.RcodeServerFailure
			break loop
		}
		loopCount++

		if h.FindZone(currentQName) != zoneName {
			logger.Default.Debugf("[%d] out of zone - qname : %s, zone : %s", context.Req.Id, currentQName, zoneName)
			res = dns.RcodeSuccess
			break loop
		}

		location, match := zone.FindLocation(currentQName)
		switch match {
		case NoMatch:
			logger.Default.Debugf("[%d] no location matched for %s in %s", context.Req.Id, currentQName, zoneName)
			context.Authority = []dns.RR{zone.Config.SOA.Data}
			res = dns.RcodeNameError
			break loop

		case WildCardMatch:
			fallthrough

		case ExactMatch:
			logger.Default.Debugf("[%d] loading location %s", context.Req.Id, location)
			currentRecord = h.LoadLocation(location, zone)
			if len(currentRecord.NS.Data) > 0 && currentQName != zone.Name {
				logger.Default.Debugf("[%d] delegation", context.Req.Id)
				context.Auth = false
				context.Authority = append(context.Authority, h.NS(currentQName, currentRecord)...)
				for _, ns := range currentRecord.NS.Data {
					glueRecord := h.LoadLocation(strings.TrimSuffix(ns.Host, "."+zone.Name), zone)
					context.Additional = append(context.Additional, h.A(ns.Host, glueRecord, glueRecord.A.Data)...)
					context.Additional = append(context.Additional, h.AAAA(ns.Host, glueRecord, glueRecord.AAAA.Data)...)
				}
				res = dns.RcodeNotAuth
				break loop
			}
			if currentRecord.CNAME != nil && context.QType() != dns.TypeCNAME {
				logger.Default.Debugf("[%d] cname chain %s -> %s", context.Req.Id, currentQName, currentRecord.CNAME.Host)
				if !zone.Config.CnameFlattening {
					context.Answer = append(context.Answer, h.CNAME(currentQName, currentRecord)...)
				} else if h.FindZone(currentRecord.CNAME.Host) != zoneName {
					context.Answer = append(context.Answer, h.CNAME(context.Name(), currentRecord)...)
					break loop
				}
				currentQName = dns.Fqdn(currentRecord.CNAME.Host)
				continue
			} else {
				logger.Default.Debugf("[%d] final location : %s", context.Req.Id, currentQName)
				if zone.Config.CnameFlattening {
					currentQName = context.Name()
				}
				var answer []dns.RR
				switch context.QType() {
				case dns.TypeA:
					var ips []IP_RR
					var ttl uint32
					if len(currentRecord.A.Data) == 0 && currentRecord.ANAME != nil {
						ips, res, ttl = h.FindANAME(context, currentRecord.ANAME.Location, dns.TypeA)
						currentRecord.A.Ttl = ttl
					} else {
						ips = h.Filter(currentRecord.Name, context.SourceIp, &currentRecord.A)
					}
					answer = h.A(currentQName, currentRecord, ips)
				case dns.TypeAAAA:
					var ips []IP_RR
					var ttl uint32
					if len(currentRecord.AAAA.Data) == 0 && currentRecord.ANAME != nil {
						ips, res, ttl = h.FindANAME(context, currentRecord.ANAME.Location, dns.TypeAAAA)
						currentRecord.AAAA.Ttl = ttl
					} else {
						ips = h.Filter(currentRecord.Name, context.SourceIp, &currentRecord.AAAA)
					}
					answer = h.AAAA(currentQName, currentRecord, ips)
				case dns.TypeCNAME:
					answer = h.CNAME(currentQName, currentRecord)
				case dns.TypeTXT:
					answer = h.TXT(currentQName, currentRecord)
				case dns.TypeNS:
					answer = h.NS(currentQName, currentRecord)
				case dns.TypeMX:
					answer = h.MX(currentQName, currentRecord)
				case dns.TypeSRV:
					answer = h.SRV(currentQName, currentRecord)
				case dns.TypeCAA:
					caaRecord := h.FindCAA(currentRecord)
					if caaRecord != nil {
						answer = h.CAA(currentQName, caaRecord)
					}
				case dns.TypePTR:
					answer = h.PTR(currentQName, currentRecord)
				case dns.TypeTLSA:
					answer = h.TLSA(currentQName, currentRecord)
				case dns.TypeSOA:
					answer = []dns.RR{zone.Config.SOA.Data}
				case dns.TypeDNSKEY:
					if zone.Config.DnsSec {
						answer = []dns.RR{zone.ZSK.DnsKey, zone.KSK.DnsKey}
					}
				default:
					context.Answer = []dns.RR{}
					res = dns.RcodeNotImplemented
				}
				context.Answer = append(context.Answer, answer...)
				if len(answer) == 0 {
					context.Authority = []dns.RR{zone.Config.SOA.Data}
				}
				break loop
			}
		}
	}

	if context.Do() && context.Auth && zone.Config.DnsSec {
		switch res {
		case dns.RcodeSuccess:
			if len(context.Answer) == 0 {
				context.Authority = append(context.Authority, NSec(context.Name(), zone))
			}
		case dns.RcodeNameError:
			context.Authority = append(context.Authority, NSec(context.Name(), zone))
			res = dns.RcodeSuccess
		}
		context.Answer = Sign(context.Answer, context.Name(), zone)
		context.Authority = Sign(context.Authority, context.Name(), zone)
		context.Additional = Sign(context.Additional, context.Name(), zone)
	}

	h.Response(context, res)
	logger.Default.Debugf("[%d] end handle request - name : %s, type : %s", context.Req.Id, context.Name(), context.Type())
}

func (h *DnsRequestHandler) Filter(name string, sourceIp net.IP, rrset *IP_RRSet) []IP_RR {
	ips := h.healthcheck.FilterHealthcheck(name, rrset)
	switch rrset.FilterConfig.GeoFilter {
	case "asn":
		ips = h.geoip.GetSameASN(sourceIp, ips)
	case "country":
		ips = h.geoip.GetSameCountry(sourceIp, ips)
	case "asn+country":
		ips = h.geoip.GetSameASN(sourceIp, ips)
		ips = h.geoip.GetSameCountry(sourceIp, ips)
	case "location":
		ips = h.geoip.GetMinimumDistance(sourceIp, ips)
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
		r.Ns = dns.Fqdn(ns.Host)
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
		r.Mx = dns.Fqdn(mx.Host)
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
		r.Target = dns.Fqdn(srv.Target)
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

func (h *DnsRequestHandler) FindZone(qname string) string {
	rname := reverseZone(qname)
	if _, zname, ok := h.Zones.Root().LongestPrefix([]byte(rname)); ok {
		return zname.(string)
	}
	return ""
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
	key := location + "." + z.Name
	cachedRecord, found := h.RecordCache.Get(key)
	if found {
		logger.Default.Debug("cached")
		return cachedRecord.(*Record)
	}
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
	if val != "" {
		err := jsoniter.Unmarshal([]byte(val), r)
		if err != nil {
			logger.Default.Errorf("cannot parse json : zone -> %s, location -> %s, \"%s\" -> %s", z.Name, location, val, err)
		}
	}

	h.RecordCache.Set(key, r, time.Duration(h.Config.CacheTimeout)*time.Second)
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
	currentLocation := strings.TrimSuffix(currentRecord.Name, "."+zone.Name)
	for {
		logger.Default.Debug("location : ", currentLocation)
		if len(currentRecord.CAA.Data) != 0 {
			return currentRecord
		}
		splits := strings.SplitAfterN(currentLocation, ".", 2)
		if len(splits) != 2 {
			break
		}
		currentLocation = splits[1]
		currentRecord = h.LoadLocation(currentLocation, zone)
	}
	currentRecord = h.LoadLocation(zone.Name, zone)
	if len(currentRecord.CAA.Data) != 0 {
		return currentRecord
	}
	return nil
}

func (h *DnsRequestHandler) FindANAME(context *RequestContext, aname string, qtype uint16) ([]IP_RR, int, uint32) {
	logger.Default.Debug("finding aname")
	currentQName := aname
	currentRecord := &Record{}
	loopCount := 0
	for {
		if loopCount > 10 {
			logger.Default.Errorf("ANAME loop in request %s->%s", context.Name(), context.Type())
			return []IP_RR{}, dns.RcodeServerFailure, 0
		}
		loopCount++

		zoneName := h.FindZone(currentQName)
		logger.Default.Debug("zone : ", zoneName, " qname : ", currentQName, " record : ", currentRecord.Name)
		if zoneName == "" {
			logger.Default.Debug("non-authoritative zone, using upstream")
			upstreamAnswers, upstreamRes := h.upstream.Query(currentQName, qtype)
			var ips []IP_RR
			var upstreamTtl uint32
			if upstreamRes == dns.RcodeSuccess {
				if len(upstreamAnswers) > 0 {
					upstreamTtl = upstreamAnswers[0].Header().Ttl
				}
				for _, r := range upstreamAnswers {
					if qtype == dns.TypeA {
						if a, ok := r.(*dns.A); ok {
							ips = append(ips, IP_RR{Ip: a.A})
						}
					} else {
						if aaaa, ok := r.(*dns.AAAA); ok {
							ips = append(ips, IP_RR{Ip: aaaa.AAAA})
						}
					}
				}
			}
			return ips, upstreamRes, upstreamTtl
		}

		zone := h.LoadZone(zoneName)
		location, _ := zone.FindLocation(currentQName)
		if location == "" {
			logger.Default.Debug("location not found")
			return []IP_RR{}, dns.RcodeNameError, 0
		}

		currentRecord = h.LoadLocation(location, zone)
		if currentRecord.CNAME != nil {
			logger.Default.Debug("cname")
			currentQName = currentRecord.CNAME.Host
			continue
		}

		if qtype == dns.TypeA && len(currentRecord.A.Data) > 0 {
			logger.Default.Debug("found a")
			return h.Filter(currentRecord.Name, context.SourceIp, &currentRecord.A), dns.RcodeSuccess, currentRecord.A.Ttl
		} else if qtype == dns.TypeAAAA && len(currentRecord.AAAA.Data) > 0 {
			logger.Default.Debug("found aaaa")
			return h.Filter(currentRecord.Name, context.SourceIp, &currentRecord.AAAA), dns.RcodeSuccess, currentRecord.AAAA.Ttl
		}

		if currentRecord.ANAME != nil {
			logger.Default.Debug("aname")
			currentQName = currentRecord.ANAME.Location
			continue
		}

		return []IP_RR{}, dns.RcodeSuccess, 0
	}
}
