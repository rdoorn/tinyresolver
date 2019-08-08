package tinyresolver

import (
	"fmt"
	"log"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testQuery struct {
	name  string
	qtype string
}

type testResult struct {
	name  string
	qtype string
	value string
}

type testRecord struct {
	query  testQuery
	answer []testResult
	ns     []testResult
	extra  []testResult
}

func TestResolving(t *testing.T) {

	records := []testRecord{
		testRecord{
			query: testQuery{
				name:  "www.ghostbox.org",
				qtype: "A",
			},
			answer: []testResult{
				testResult{
					name:  "www.ghostbox.org.",
					qtype: "A",
					value: "95.142.102.175",
				},
			},
			ns: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "NS",
					value: "q3.ghostbox.org",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "www.ghostbox.org",
				qtype: "A",
			},
			answer: []testResult{
				testResult{
					name:  "www.ghostbox.org.",
					qtype: "A",
					value: "95.142.102.175",
				},
			},
			/*ns: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "NS",
					value: "q3.ghostbox.org",
				},
			},*/
		},

		testRecord{
			query: testQuery{
				name:  "ghostbox.org",
				qtype: "MX",
			},
			answer: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "MX",
					value: "20 mx2.ghostbox.org.",
				},
			},
			extra: []testResult{
				testResult{
					name:  "mx2.ghostbox.org.",
					qtype: "A",
					value: "95.142.102.176",
				},
			},
		},
	}

	resolver := New()

	t.Run("testResolving", func(t *testing.T) {
		for _, record := range records {
			// execute valid requests
			t.Run(fmt.Sprintf("testResolving/%s_%s", record.query.name, record.query.qtype), func(t *testing.T) {
				resolver.testResolving(t, record)
			})
		}
	})
}

func (r *Resolver) testResolving(t *testing.T, record testRecord) {
	rrs, err := r.Resolve(record.query.name, record.query.qtype)
	log.Printf("rr: %+v err:%s", rrs, err)

	for _, result := range record.answer {
		ok := 0
		for _, rr := range rrs.Answer {
			//r, err := regexp.Compile(fmt.Sprintf("/%s\\t\\d+.*%s.*%s/", result.name, result.qtype, result.value))
			r, err := regexp.Compile(fmt.Sprintf("^%s\\t+\\d+.*%s\\s+%s", result.name, result.qtype, result.value))
			assert.Nil(t, err)
			//if rr.String()
			if r.MatchString(rr.String()) {
				ok++
			}
		}
		assert.Equal(t, len(record.answer), ok)
	}

	for _, result := range record.ns {
		ok := 0
		for _, rr := range rrs.Ns {
			//r, err := regexp.Compile(fmt.Sprintf("/%s\\t\\d+.*%s.*%s/", result.name, result.qtype, result.value))
			r, err := regexp.Compile(fmt.Sprintf("^%s\\t+\\d+.*%s\\s+%s", result.name, result.qtype, result.value))
			assert.Nil(t, err)
			//if rr.String()
			if r.MatchString(rr.String()) {
				ok++
			}
		}
		assert.Equal(t, len(record.ns), ok)
	}

	for _, result := range record.extra {
		ok := 0
		for _, rr := range rrs.Extra {
			//r, err := regexp.Compile(fmt.Sprintf("/%s\\t\\d+.*%s.*%s/", result.name, result.qtype, result.value))
			r, err := regexp.Compile(fmt.Sprintf("^%s\\t+\\d+.*%s\\s+%s", result.name, result.qtype, result.value))
			assert.Nil(t, err)
			//if rr.String()
			if r.MatchString(rr.String()) {
				ok++
			}
		}
		assert.Equal(t, len(record.extra), ok)
	}

}
