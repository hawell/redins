package tool

import (
	"arvancloud/redins/tools/query/query"
	"github.com/miekg/dns"
)

type QueryTool interface {
	Act(q query.Query, client *dns.Client)
	Result()
}

