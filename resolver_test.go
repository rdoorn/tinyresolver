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

		testRecord{
			query: testQuery{
				name:  "ghostbox.org",
				qtype: "NS",
			},
			answer: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "NS",
					value: "q3.ghostbox.org.",
				},
			},
			extra: []testResult{
				testResult{
					name:  "q3.ghostbox.org.",
					qtype: "A",
					value: "95.142.102.175",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "ghostbox.org",
				qtype: "NS",
			},
			answer: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "NS",
					value: "q3.ghostbox.org.",
				},
			},
			extra: []testResult{
				testResult{
					name:  "q3.ghostbox.org.",
					qtype: "A",
					value: "95.142.102.175",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "noname.ghostbox.org",
				qtype: "A",
			},
			answer: []testResult{
				testResult{
					name:  "noname.ghostbox.org.",
					qtype: "CNAME",
					value: "ghostbox.org",
				},
				testResult{
					name:  "ghostbox.org.",
					qtype: "A",
					value: "95.142.102.175",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "noname.ghostbox.org",
				qtype: "A",
			},
			answer: []testResult{
				testResult{
					name:  "noname.ghostbox.org.",
					qtype: "CNAME",
					value: "ghostbox.org",
				},
				testResult{
					name:  "ghostbox.org.",
					qtype: "A",
					value: "95.142.102.175",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "noname.ghostbox.org",
				qtype: "CNAME",
			},
			answer: []testResult{
				testResult{
					name:  "noname.ghostbox.org.",
					qtype: "CNAME",
					value: "ghostbox.org",
				},
			},
			extra: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "A",
					value: "95.142.102.175",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "noname.ghostbox.org",
				qtype: "CNAME",
			},
			answer: []testResult{
				testResult{
					name:  "noname.ghostbox.org.",
					qtype: "CNAME",
					value: "ghostbox.org",
				},
			},
			extra: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "A",
					value: "95.142.102.175",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "ghostbox.org",
				qtype: "SOA",
			},
			answer: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "SOA",
					value: "q1.ghostbox.org.",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "ghostbox.org",
				qtype: "SOA",
			},
			answer: []testResult{
				testResult{
					name:  "ghostbox.org.",
					qtype: "SOA",
					value: "q1.ghostbox.org.",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "ghostboxnotexisting.org",
				qtype: "A",
			},
			ns: []testResult{
				testResult{
					name:  "org.",
					qtype: "SOA",
					value: "",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "ghostboxnotexisting.org",
				qtype: "A",
			},
			ns: []testResult{
				testResult{
					name:  "org.",
					qtype: "SOA",
					value: "",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "175.102.142.95.in-addr.arpa",
				qtype: "PTR",
			},
			answer: []testResult{
				testResult{
					name:  "175.102.142.95.in-addr.arpa.",
					qtype: "PTR",
					value: "a4091.mcehosting.atom86.net.",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "175.102.142.95.in-addr.arpa",
				qtype: "PTR",
			},
			answer: []testResult{
				testResult{
					name:  "175.102.142.95.in-addr.arpa.",
					qtype: "PTR",
					value: "a4091.mcehosting.atom86.net.",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "175.102.142.95.in-addr.arpa",
				qtype: "A",
			},
			ns: []testResult{
				testResult{
					name:  "102.142.95.in-addr.arpa.",
					qtype: "SOA",
					value: "ns1.atom86.net.",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "102.142.95.in-addr.arpa",
				qtype: "NS",
			},
			answer: []testResult{
				testResult{
					name:  "102.142.95.in-addr.arpa.",
					qtype: "NS",
					value: "ns1.atom86.net.",
				},
			},
		},
		testRecord{
			query: testQuery{
				name:  "102.142.95.in-addr.arpa",
				qtype: "NS",
			},
			answer: []testResult{
				testResult{
					name:  "102.142.95.in-addr.arpa.",
					qtype: "NS",
					value: "ns1.atom86.net.",
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

	assert.Nil(t, err)
	if rrs == nil {
		assert.FailNow(t, "failed to resolve")
	}

	for _, result := range record.answer {
		ok := 0
		for _, rr := range rrs.Answer {
			//r, err := regexp.Compile(fmt.Sprintf("/%s\\t\\d+.*%s.*%s/", result.name, result.qtype, result.value))
			r, err := regexp.Compile(fmt.Sprintf("^%s\\t+\\d+.*%s\\t+%s", result.name, result.qtype, result.value))
			assert.Nil(t, err)
			//if rr.String()
			if r.MatchString(rr.String()) {
				ok++
			}
		}
		assert.Equal(t, 1, ok, "answer record")
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
		assert.Equal(t, 1, ok, "ns record")
	}

	for _, result := range record.extra {
		ok := 0
		for _, rr := range rrs.Extra {
			r, err := regexp.Compile(fmt.Sprintf("^%s\\t+\\d+.*%s\\s+%s", result.name, result.qtype, result.value))
			assert.Nil(t, err)
			//if rr.String()
			if r.MatchString(rr.String()) {
				ok++
			}
		}
		assert.Equal(t, 1, ok, "extra record")
	}

}
