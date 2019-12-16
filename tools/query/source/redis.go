package source

import (
	"arvancloud/redins/tools/query/query"
	"github.com/hawell/uperdis"
)

type RedisDumpQueryGenerator struct {
	redisAddress string
	queries []query.Query
	pos int
}

func NewRedisDumpQueryGenerator(redisAddress string) *RedisDumpQueryGenerator {
	redis := uperdis.NewRedis(&uperdis.RedisConfig{
		Address:  redisAddress,
		Net:      "tcp",
		DB:       0,
		Password: "",
		Prefix:   "",
		Suffix:   "_dns2",
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
	g := new(RedisDumpQueryGenerator)
	zones, _ := redis.SMembers("redins:zones")
	for _, zone := range zones {
		locations, _ := redis.GetHKeys("redins:zones:" + zone)
		for _, location := range locations {
			qname := ""
			if location == "@" {
				qname = zone
			} else {
				qname = location + "." + zone
			}
			g.queries = append(g.queries, query.Query{QName: qname, QType: "A"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "AAAA"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "CNAME"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "NS"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "MX"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "SRV"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "TXT"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "PTR"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "CAA"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "TLSA"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "SOA"})
			g.queries = append(g.queries, query.Query{QName: qname, QType: "DNSKEY"})
		}
	}
	return g
}

func (g *RedisDumpQueryGenerator) Init() {

}

func (g *RedisDumpQueryGenerator) Count() int {
	return len(g.queries)
}

func (g *RedisDumpQueryGenerator) GetQuery() query.Query {
	q := g.queries[g.pos]
	g.pos++
	return q
}

