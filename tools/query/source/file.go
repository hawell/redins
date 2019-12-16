package source

import (
	"arvancloud/redins/tools/query/query"
	"bufio"
	"fmt"
	"math/rand"
	"os"
)

type FileQueryGenerator struct {
	queries []query.Query
	count int
	zipf *rand.Zipf
}

func NewFileQueryGenerator(path string, count int) *FileQueryGenerator {
	g := &FileQueryGenerator{
		count: count,
	}

	f, _ := os.Open(path)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		var q query.Query
		line := scanner.Text()
		if _, err := fmt.Sscanf(line,"%s%s", &q.QName, &q.QType); err != nil {
			fmt.Println(err)
		}
		// fmt.Println(q)
		g.queries = append(g.queries, q)
	}

	f.Close()

	source := rand.NewSource(rand.Int63n(30))
	r := rand.New(source)
	g.zipf = rand.NewZipf(r, 1.00001, 1, uint64(len(g.queries)-1))

	return g
}

func (g *FileQueryGenerator) Init() {

}

func (g *FileQueryGenerator) Count() int {
	return g.count
}

func (g *FileQueryGenerator) GetQuery() query.Query {
	z := g.zipf.Uint64()
	// fmt.Println(z)
	return g.queries[z]
}

