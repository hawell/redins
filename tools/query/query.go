package main

import (
	"arvancloud/redins/tools/query/query"
	"arvancloud/redins/tools/query/source"
	"arvancloud/redins/tools/query/tool"
	"flag"
	"fmt"
	"github.com/hawell/workerpool"
	"github.com/miekg/dns"
	"time"
)

func main() {
	sourcePtr := flag.String("source", "redis", "data source: redis, file")
	toolPtr := flag.String("tool", "bench", "tool: bench, compare")
	s1AddrPtr := flag.String("s1", "localhost:1053", "server 1")
	s2AddrPtr := flag.String("s2", "localhost:2053", "server 2")
	sourceAddrPtr := flag.String("source-address", "localhost:6379", "source address")
	MaxWorkersPtr := flag.Int("threads", 10, "number of threads")
	MaxQueries := flag.Int("max-queries", 1000000, "maximum queries")

	flag.Parse()

	var g source.QueryGenerator
	switch *sourcePtr {
	case "redis":
		g = source.NewRedisDumpQueryGenerator(*sourceAddrPtr)
	case "file":
		g = source.NewFileQueryGenerator(*sourceAddrPtr, *MaxQueries)
	default:
		fmt.Println("invalid query source : ", *sourcePtr)
		return
	}

	var t tool.QueryTool
	switch *toolPtr {
	case "compare":
		t = tool.NewCompareTool(*s1AddrPtr, *s2AddrPtr)
	case "bench":
		t = tool.NewBenchTool(*s1AddrPtr)
	default:
		fmt.Println("invalid tool : ", *toolPtr)
		return
	}

	maxWorkers := *MaxWorkersPtr

	dispatcher := workerpool.NewDispatcher(10000, maxWorkers)
	var count []int
	var clients []*dns.Client
	handler := func(worker *workerpool.Worker, job workerpool.Job) {
		q := job.(query.Query)
		count[worker.Id]++
		//fmt.Println(q)
		t.Act(q,clients[worker.Id])
	}
	for i := 0; i < maxWorkers; i++ {
		client := &dns.Client{
			Net:     "udp",
			Timeout: time.Millisecond * 4000,
		}
		clients = append(clients, client)
		dispatcher.AddWorker(handler)
		count = append(count, 0)
	}

	dispatcher.Run()
	for i := 0; i < g.Count(); i++ {
		dispatcher.Queue(g.GetQuery())
	}
	var totalCount int
	for totalCount != g.Count() {
		totalCount = 0
		for _, c := range count {
			totalCount += c
		}
		time.Sleep(time.Second)
	}
	time.Sleep(time.Second)

	fmt.Println("total : ", count)
	t.Result()
}
