package source

import "arvancloud/redins/tools/query/query"

type QueryGenerator interface {
	Init()
	Count() int
	GetQuery() query.Query
}

