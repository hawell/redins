package handler

import (
	"crypto/tls"
	"fmt"
	"github.com/json-iterator/go"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"encoding/binary"
	"github.com/hawell/logger"
	"github.com/hawell/uperdis"
	"github.com/hawell/workerpool"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type HealthCheckItem struct {
	Protocol  string    `json:"protocol,omitempty"`
	Uri       string    `json:"uri,omitempty"`
	Port      int       `json:"port,omitempty"`
	Status    int       `json:"status,omitempty"`
	LastCheck time.Time `json:"lastcheck,omitempty"`
	Timeout   int       `json:"timeout,omitempty"`
	UpCount   int       `json:"up_count,omitempty"`
	DownCount int       `json:"down_count,omitempty"`
	Enable    bool      `json:"enable,omitempty"`
	DomainId  string    `json:"domain_uuid, omitempty"`
	Host      string    `json:"-"`
	Ip        string    `json:"-"`
	Error     error     `json:"-"`
}

type Healthcheck struct {
	Enable             bool
	maxRequests        int
	maxPendingRequests int
	updateInterval     time.Duration
	checkInterval      time.Duration
	redisConfigServer  *uperdis.Redis
	redisStatusServer  *uperdis.Redis
	logger             *logger.EventLogger
	cachedItems        *cache.Cache
	lastUpdate         time.Time
	dispatcher         *workerpool.Dispatcher
	quit               chan struct{}
	quitWG             sync.WaitGroup
}

func HandleHealthCheck(h *Healthcheck) workerpool.JobHandler {
	return func(worker *workerpool.Worker, job workerpool.Job) {
		item := job.(*HealthCheckItem)
		logger.Default.Debugf("item %v received", item)
		var err error
		switch item.Protocol {
		case "http", "https":
			timeout := time.Duration(item.Timeout) * time.Millisecond
			url := item.Protocol + "://" + item.Ip + item.Uri
			err = httpCheck(url, item.Host, timeout)
		case "ping", "icmp":
			err = pingCheck(item.Ip, time.Duration(item.Timeout)*time.Millisecond)
			logger.Default.Error("@@@@@@@@@@@@@@ ", item.Ip, " : result : ", err)
		default:
			err = errors.New(fmt.Sprintf("invalid protocol : %s used for %s:%d", item.Protocol, item.Ip, item.Port))
			logger.Default.Error(err)
		}
		item.Error = err
		if err == nil {
			statusUp(item)
		} else {
			statusDown(item)
		}
		item.LastCheck = time.Now()
		h.storeItem(item)
		h.logHealthcheck(item)
	}
}

func httpCheck(url string, host string, timeout time.Duration) error {
	tr := &http.Transport{
		MaxIdleConnsPerHost: 1024,
		TLSHandshakeTimeout: 0 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		logger.Default.Errorf("invalid request, host:%s, url:%s : %s", host, url, err)
		return err
	}
	req.Host = strings.TrimRight(host, ".")
	resp, err := client.Do(req)
	if err != nil {
		logger.Default.Errorf("request failed, host:%s, url:%s : %s", host, url, err)
		return err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusFound, http.StatusMovedPermanently:
		return nil
	default:
		return errors.New(fmt.Sprintf("invalid http status code : %d", resp.StatusCode))
	}
}

// FIXME: ping check is not working properly
func pingCheck(ip string, timeout time.Duration) error {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	c.SetDeadline(time.Now().Add(timeout))
	defer c.Close()

	id := int(binary.BigEndian.Uint32(net.ParseIP(ip)))
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(ip)}); err != nil {
		return err
	}

	rb := make([]byte, 1500)
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return err
	}
	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
	if err != nil {
		return err
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		logger.Default.Error("@@@@@@@@@@@@ code = ", rm.Code)
		return nil
	default:
		return errors.New(fmt.Sprintf("got %+v; want echo reply", rm))
	}
}

type HealthcheckConfig struct {
	Enable             bool                `json:"enable"`
	MaxRequests        int                 `json:"max_requests"`
	MaxPendingRequests int                 `json:"max_pending_requests"`
	UpdateInterval     int                 `json:"update_interval"`
	CheckInterval      int                 `json:"check_interval"`
	RedisStatusServer  uperdis.RedisConfig `json:"redis"`
	Log                logger.LogConfig    `json:"log"`
}

func NewHealthcheck(config *HealthcheckConfig, redisConfigServer *uperdis.Redis) *Healthcheck {
	h := &Healthcheck{
		Enable:             config.Enable,
		maxRequests:        config.MaxRequests,
		maxPendingRequests: config.MaxPendingRequests,
		updateInterval:     time.Duration(config.UpdateInterval) * time.Second,
		checkInterval:      time.Duration(config.CheckInterval) * time.Second,
	}

	if h.Enable {

		h.redisConfigServer = redisConfigServer
		h.redisStatusServer = uperdis.NewRedis(&config.RedisStatusServer)
		h.cachedItems = cache.New(h.updateInterval, h.updateInterval*10)
		h.dispatcher = workerpool.NewDispatcher(config.MaxPendingRequests, config.MaxRequests)
		for i := 0; i < config.MaxRequests; i++ {
			h.dispatcher.AddWorker(HandleHealthCheck(h))
		}
		h.logger = logger.NewLogger(&config.Log, nil)
		h.quit = make(chan struct{}, 1)
	}

	return h
}

func (h *Healthcheck) ShutDown() {
	if !h.Enable {
		return
	}
	// fmt.Println("healthcheck : stopping")
	h.dispatcher.Stop()
	h.quitWG.Add(2) // one for h.dispatcher.Start(), another for h.Transfer()
	close(h.quit)
	h.quitWG.Wait()
	// fmt.Println("healthcheck : stopped")
}

func (h *Healthcheck) getStatus(host string, ip net.IP) int {
	if !h.Enable {
		return 0
	}
	key := host + ":" + ip.String()
	var item *HealthCheckItem
	val, found := h.cachedItems.Get(key)
	if !found {
		item = h.loadItem(key)
		if item == nil {
			item = new(HealthCheckItem)
		}
		h.cachedItems.Set(key, item, h.updateInterval)
	} else {
		item = val.(*HealthCheckItem)
	}
	return item.Status
}

func (h *Healthcheck) loadItem(key string) *HealthCheckItem {
	splits := strings.SplitAfterN(key, ":", 2)
	// logger.Default.Error(splits)
	if len(splits) != 2 {
		logger.Default.Errorf("invalid key: %s", key)
		return nil
	}
	item := new(HealthCheckItem)
	item.Host = strings.TrimSuffix(splits[0], ":")
	item.Ip = splits[1]
	itemStr, err := h.redisStatusServer.Get("redins:healthcheck:" + key)
	if err != nil {
		logger.Default.Errorf("cannot load item %s : %s", key, err)
		return nil
	}
	jsoniter.Unmarshal([]byte(itemStr), item)
	if item.DownCount > 0 {
		item.DownCount = -item.DownCount
	}
	return item
}

func (h *Healthcheck) storeItem(item *HealthCheckItem) {
	key := item.Host + ":" + item.Ip
	itemStr, err := jsoniter.Marshal(item)
	if err != nil {
		logger.Default.Errorf("cannot marshal item to json : %s", err)
		return
	}
	logger.Default.Debugf("setting %v in redis : %s", *item, string(itemStr))
	h.redisStatusServer.Set("redins:healthcheck:"+key, string(itemStr))
}

func (h *Healthcheck) getDomainId(zone string) string {
	var cfg ZoneConfig
	val, err := h.redisConfigServer.Get("redins:zones:" + zone + ":config")
	if err != nil {
		logger.Default.Errorf("cannot load zone %s config : %s", zone, err)
	}
	if len(val) > 0 {
		err := jsoniter.Unmarshal([]byte(val), &cfg)
		if err != nil {
			logger.Default.Errorf("cannot parse zone config : %s", err)
		}
	}
	return cfg.DomainId
}

func (h *Healthcheck) Start() {
	if !h.Enable {
		return
	}
	h.dispatcher.Run()

	go h.Transfer()

	ticker := time.NewTicker(h.checkInterval)
	for {
		itemKeys, err := h.redisStatusServer.GetKeys("redins:healthcheck:*")
		if err != nil {
			logger.Default.Errorf("cannot load keys : redins:healthcheck:* : %s", err)
		}
		select {
		case <-h.quit:
			ticker.Stop()
			h.quitWG.Done()
			return
		case <-ticker.C:
			for i := range itemKeys {
				itemKey := strings.TrimPrefix(itemKeys[i], "redins:healthcheck:")
				item := h.loadItem(itemKey)
				if item != nil {
					if time.Since(item.LastCheck) > h.checkInterval {
						h.dispatcher.Queue(item)
					}
				}
			}
		}
	}

}

func (h *Healthcheck) logHealthcheck(item *HealthCheckItem) {
	data := map[string]interface{}{
		"ip":          item.Ip,
		"port":        item.Port,
		"host":        item.Host,
		"domain_uuid": item.DomainId,
		"uri":         item.Uri,
		"status":      item.Status,
		"log_type":    "healthcheck",
	}
	if item.Error == nil {
		data["error"] = ""
	} else {
		data["error"] = item.Error.Error()
	}

	h.logger.Log(data, "dns healthcheck")
}

func statusDown(item *HealthCheckItem) {
	if item.Status <= 0 {
		item.Status--
		if item.Status < item.DownCount {
			item.Status = item.DownCount
		}
	} else {
		item.Status = -1
	}
}

func statusUp(item *HealthCheckItem) {
	if item.Status >= 0 {
		item.Status++
		if item.Status > item.UpCount {
			item.Status = item.UpCount
		}
	} else {
		item.Status = 1
	}
}

func (h *Healthcheck) FilterHealthcheck(qname string, rrset *IP_RRSet) []IP_RR {
	var newIps []IP_RR
	if !h.Enable {
		newIps = append(newIps, rrset.Data...)
		return newIps
	}
	min := rrset.HealthCheckConfig.DownCount
	for _, ip := range rrset.Data {
		status := h.getStatus(qname, ip.Ip)
		if status > min {
			min = status
		}
	}
	logger.Default.Debugf("min = %d", min)
	if min < rrset.HealthCheckConfig.UpCount-1 && min > rrset.HealthCheckConfig.DownCount {
		min = rrset.HealthCheckConfig.DownCount + 1
	}
	logger.Default.Debugf("min = %d", min)
	for _, ip := range rrset.Data {
		logger.Default.Debug("qname: ", ip.Ip.String(), " status: ", h.getStatus(qname, ip.Ip))
		if h.getStatus(qname, ip.Ip) < min {
			continue
		}
		newIps = append(newIps, ip)
	}
	return newIps
}

func (h *Healthcheck) Transfer() {
	itemsEqual := func(item1 *HealthCheckItem, item2 *HealthCheckItem) bool {
		if item1 == nil || item2 == nil {
			return false
		}
		if item1.Ip != item2.Ip || item1.Uri != item2.Uri || item1.Port != item2.Port ||
			item1.Protocol != item2.Protocol || item1.Enable != item2.Enable ||
			item1.UpCount != item2.UpCount || item1.DownCount != item2.DownCount || item1.Timeout != item2.Timeout {
			return false
		}
		return true
	}

	limiter := time.Tick(time.Millisecond * 50)
	for {
		domains, err := h.redisConfigServer.SMembers("redins:zones")
		if err != nil {
			logger.Default.Errorf("cannot get members of redins:zones : %s", err)
		}
		for _, domain := range domains {
			domainId := h.getDomainId(domain)
			subdomains, err := h.redisConfigServer.GetHKeys("redins:zones:" + domain)
			if err != nil {
				logger.Default.Errorf("cannot get keys of %s : %s", domain, err)
			}
			for _, subdomain := range subdomains {
				select {
				case <-h.quit:
					h.quitWG.Done()
					return
				case <-limiter:
					recordStr, err := h.redisConfigServer.HGet("redins:zones:"+domain, subdomain)
					if err != nil {
						logger.Default.Errorf("cannot get record of %s.%s : %s", subdomain, domain, err)
					}
					record := new(Record)
					record.A.HealthCheckConfig = IpHealthCheckConfig{
						Timeout:   1000,
						Port:      80,
						UpCount:   3,
						DownCount: -3,
						Protocol:  "http",
						Uri:       "/",
						Enable:    false,
					}
					record.AAAA = record.A
					err = jsoniter.Unmarshal([]byte(recordStr), record)
					if err != nil {
						logger.Default.Errorf("cannot parse json : zone -> %s, location -> %s, %s -> %s", domain, subdomain, recordStr, err)
						continue
					}
					var host string
					if subdomain == "@" {
						host = domain
					} else {
						host = subdomain + "." + domain
					}
					for _, rrset := range []*IP_RRSet{&record.A, &record.AAAA} {
						if !rrset.HealthCheckConfig.Enable {
							continue
						}
						for i := range rrset.Data {
							key := host + ":" + rrset.Data[i].Ip.String()
							newItem := &HealthCheckItem{
								Ip:        rrset.Data[i].Ip.String(),
								Port:      rrset.HealthCheckConfig.Port,
								Host:      host,
								Enable:    rrset.HealthCheckConfig.Enable,
								DownCount: rrset.HealthCheckConfig.DownCount,
								UpCount:   rrset.HealthCheckConfig.UpCount,
								Timeout:   rrset.HealthCheckConfig.Timeout,
								Uri:       rrset.HealthCheckConfig.Uri,
								Protocol:  rrset.HealthCheckConfig.Protocol,
								DomainId:  domainId,
							}
							oldItem := h.loadItem(key)
							if !itemsEqual(oldItem, newItem) {
								h.storeItem(newItem)
							}
							h.redisStatusServer.Expire("redins:healthcheck:"+key, h.updateInterval)
						}
					}
				}
			}
		}
	}
}
