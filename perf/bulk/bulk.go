package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"os"
	"time"
)

type query struct {
	queryAddr   string
	queryType   int
	resultCode  int
	queryResult string
}

func main() {
	numQueries := flag.Int64("num", 10000, "number of queries")
	flag.Parse()

	client := &dns.Client{
		Net:     "udp",
		Timeout: time.Millisecond * 100,
	}

	var queries []query

	fq, err := os.Open("../query.txt")
	if err != nil {
		fmt.Println("cannot open query.txt")
		return
	}
	defer fq.Close()
	rq := bufio.NewReader(fq)
	var duration time.Duration
	for {
		line, err := rq.ReadString('\n')
		if err != nil {
			break
		}
		var q query
		// fmt.Println("line = ", line)
		fmt.Sscan(line, &q.queryAddr, &q.queryType, &q.resultCode, &q.queryResult)
		// fmt.Println("addr = ", queryAddr, "result = ", queryResult)
		queries = append(queries, q)
	}
	fmt.Println(*numQueries)
	for i := int64(0); i < *numQueries; i++ {
		if i%1000000 == 0 {
			println(i)
		}
		q := queries[rand.Int()%len(queries)]
		m := new(dns.Msg)
		m.SetQuestion(q.queryAddr, uint16(q.queryType))
		r, rtt, err := client.Exchange(m, "localhost:1053")
		if err != nil {
			fmt.Println("error: ", err, " ", q.queryAddr)
			continue
		}
		if r.Rcode != q.resultCode {
			fmt.Println("bad response : ", r.Rcode)
			break
		}
		if q.resultCode == dns.RcodeSuccess {
			if len(r.Answer) == 0 {
				fmt.Println("empty response")
				break
			}
			switch uint16(q.queryType) {
			case dns.TypeA:
				a := r.Answer[0].(*dns.A)
				if a.A.String() != q.queryResult {
					fmt.Printf("error: incorrect answer : expected %s got %s", q.queryResult, a.A.String())
					break
				}
			case dns.TypeTXT:
				txt := r.Answer[0].(*dns.TXT)
				if txt.Txt[0] != q.queryResult {
					fmt.Printf("error: incorrect answer : expected %s got %s", q.queryResult, txt.Txt[0])
					break
				}
			}
			duration += rtt
		}
	}
	fmt.Println(duration)
}
