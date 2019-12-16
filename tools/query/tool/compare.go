package tool

import (
	"arvancloud/redins/test"
	"arvancloud/redins/tools/query/query"
	"fmt"
	"github.com/miekg/dns"
	"sort"
)

type CompareTool struct {
	server1Address string
	server2Address string
}

func NewCompareTool(s1 string, s2 string) *CompareTool {
	t := &CompareTool{
		server1Address: s1,
		server2Address: s2,
	}
	return t
}

func (t *CompareTool) Act(q query.Query, client *dns.Client) {
	m := new(dns.Msg)
	m.SetQuestion(q.QName, dns.StringToType[q.QType])
	//fmt.Println(m)
	resp1, _, err1 := client.Exchange(m, t.server1Address)
	resp2, _, err2 := client.Exchange(m, t.server2Address)
	if err1 != err2 {
		fmt.Println(q.QName, "->", q.QType, " : ", err1, " != ", err2)
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
			fmt.Println(q.QName, "->", q.QType, " : ", err)
		}
	}
}

func (t *CompareTool) Result() {

}

