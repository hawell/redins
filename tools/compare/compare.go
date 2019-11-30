package main

import (
	"arvancloud/redins/test"
	"flag"
	"fmt"
	"github.com/hawell/uperdis"
	"github.com/hawell/workerpool"
	"github.com/miekg/dns"
	"sort"
	"time"
)

type query struct {
	qname string
	qtype string
}

func main() {
	s1AddrPtr := flag.String("s1", "localhost:1053", "server 1")
	s2AddrPtr := flag.String("s2", "localhost:2053", "server 2")
	redisAddrPtr := flag.String("redis", "localhost:6379", "redis address")
	MaxWorkersPtr := flag.Int("threads", 10, "number of threads")

	flag.Parse()

	maxWorkers := *MaxWorkersPtr
	var queries []query
	redis := uperdis.NewRedis(&uperdis.RedisConfig{
		Address:    *redisAddrPtr,
		Net:        "tcp",
		DB:         0,
		Password:   "",
		Prefix:     "",
		Suffix:     "_dns2",
		Connection: uperdis.RedisConnectionConfig{
			MaxIdleConnections:   10,
			MaxActiveConnections: 10,
			ConnectTimeout:       500,
			ReadTimeout:          500,
			IdleKeepAlive:        30,
			MaxKeepAlive:         0,
			WaitForConnection:    false,
		},
	})
	zones, _ := redis.SMembers("redins:zones")
	for _, zone := range zones {
		locations, _ := redis.GetHKeys("redins:zones:" + zone)
		for _, location := range locations {
			qname := ""
			if location == "@" {
				qname = zone
			} else {
				qname = location+"."+zone
			}
			queries = append(queries, query{qname:qname, qtype:"A"})
			queries = append(queries, query{qname:qname, qtype:"AAAA"})
			queries = append(queries, query{qname:qname, qtype:"CNAME"})
			queries = append(queries, query{qname:qname, qtype:"NS"})
			queries = append(queries, query{qname:qname, qtype:"MX"})
			queries = append(queries, query{qname:qname, qtype:"SRV"})
			queries = append(queries, query{qname:qname, qtype:"TXT"})
			queries = append(queries, query{qname:qname, qtype:"PTR"})
			queries = append(queries, query{qname:qname, qtype:"CAA"})
			queries = append(queries, query{qname:qname, qtype:"TLSA"})
			queries = append(queries, query{qname:qname, qtype:"SOA"})
			queries = append(queries, query{qname:qname, qtype:"DNSKEY"})
		}
	}


	client := &dns.Client{
		Net:     "udp",
		Timeout: time.Millisecond * 4000,
	}

	dispatcher := workerpool.NewDispatcher(10000, maxWorkers)
	var count []int
	handler := func(worker *workerpool.Worker, job workerpool.Job) {
		q := job.(query)
		count[worker.Id]++
		//fmt.Println(q)
		m := new(dns.Msg)
		m.SetQuestion(q.qname, dns.StringToType[q.qtype])
		//fmt.Println(m)
		resp1, _, err1 := client.Exchange(m, *s1AddrPtr)
		resp2, _, err2 := client.Exchange(m, *s2AddrPtr)
		if err1 != err2 {
			// fmt.Println(q.qname, "->", q.qtype, " : ", err1, " != ", err2)
		} else if err1 == nil {
			sort.Sort(test.RRSet(resp1.Answer))
			sort.Sort(test.RRSet(resp1.Ns))
			sort.Sort(test.RRSet(resp1.Extra))
			tc := test.Case{
				Qname:  resp1.Question[0].Name,
				Qtype:  resp1.Question[0].Qtype,
				Rcode:  resp1.Rcode,
				Do:     false,
				Answer: resp1.Answer,
				Ns:     resp1.Ns,
				Extra:  resp1.Extra,
				Error:  nil,
			}
			if err := test.SortAndCheck(resp2, tc); err != nil {
				fmt.Println(q.qname, "->", q.qtype, " : ", err)
			}
		}
	}
	for i := 0; i<maxWorkers; i++ {
		dispatcher.AddWorker(handler)
		count = append(count, 0)
	}

	dispatcher.Run()
	for _, q := range queries {
		dispatcher.Queue(q)
	}
	var totalCount int
	for totalCount != len(queries) {
		totalCount = 0
		for _, c := range count {
			totalCount += c
		}
		time.Sleep(time.Second)
	}
	time.Sleep(time.Second)

	fmt.Println("total : ", count)
}
