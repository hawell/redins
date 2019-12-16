package tool

import (
	"arvancloud/redins/tools/query/query"
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"time"
)

type BenchTool struct {
	count int
	totalTime time.Duration
	min time.Duration
	max time.Duration
	mean float64
	stdev float64
	serverAddress string
	mutex sync.Mutex
}

func NewBenchTool(serverAddress string) *BenchTool {
	return &BenchTool{
		min:       1000,
		serverAddress: serverAddress,
	}
}

func (t *BenchTool) Act(q query.Query, client *dns.Client) {
	m := new(dns.Msg)
	m.SetQuestion(q.QName, dns.StringToType[q.QType])
	//fmt.Println(m)
	_, rtt, err := client.Exchange(m, t.serverAddress)
	if err != nil {
		fmt.Println(err)
	}
	t.mutex.Lock()
	prevMean := t.mean
	t.count++
	x := rtt.Seconds()
	t.mean = t.mean + (x-t.mean) / float64(t.count)
	t.stdev = t.stdev + (x-t.mean)*(x-prevMean)
	if rtt < t.min {
		t.min = rtt
	}
	if rtt > t.max {
		t.max = rtt
	}
	t.totalTime += rtt
	t.mutex.Unlock()
}

func (t *BenchTool) Result() {
	fmt.Println("total time : ", t.totalTime)
	fmt.Println("min : ", t.min)
	fmt.Println("max : ", t.max)
	fmt.Println("mean : ", t.mean*1000000, " us")
	fmt.Println("stdev : ", t.stdev*1000, " ms")
}
