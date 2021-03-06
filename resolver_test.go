package tinyresolver

import (
	"fmt"
	"log"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testQuery struct {
	name  string
	qtype string
	debug bool
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
				name:  "org.",
				qtype: "NS",
				//debug: true,
			},
			answer: []testResult{
				testResult{
					name:  "org.",
					qtype: "NS",
					value: "a2.org.afilias-nst.info.",
				},
			},
		},

		testRecord{
			query: testQuery{
				name:  "www.ghostbox.org",
				qtype: "A",
				//debug: true,
			},
			answer: []testResult{
				testResult{
					name:  "www.ghostbox.org.",
					qtype: "CNAME",
					value: "ghostbox.org",
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

		/*
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

			testRecord{
				query: testQuery{
					name:  "dns.tiscali.it.",
					qtype: "NS",
				},
				answer: []testResult{
					testResult{
						name:  "dns.tiscali.it.",
						qtype: "NS",
						value: "hannibal.dns.tiscali.it.",
					},
				},
				extra: []testResult{
					testResult{
						name:  "hannibal.dns.tiscali.it.",
						qtype: "A",
						value: "94.32.102.60",
					},
				},
			},

			testRecord{
				query: testQuery{
					name:  "graph.facebook.com",
					qtype: "A",
				},
				answer: []testResult{
					testResult{
						name:  "graph.facebook.com.",
						qtype: "CNAME",
						value: "api.facebook.com.",
					},
					testResult{
						name:  "api.facebook.com.",
						qtype: "CNAME",
						value: "star.c10r.facebook.com.",
					},
					testResult{
						name:  "star.c10r.facebook.com.",
						qtype: "A",
						value: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
					},
				},
			},

			testRecord{
				query: testQuery{
					name:  "google.com",
					qtype: "A",
				},
				answer: []testResult{
					testResult{
						name:  "google.com.",
						qtype: "A",
						value: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
					},
				},
			},

			testRecord{
				query: testQuery{
					name:  "ns1-2.akamai.com.",
					qtype: "A",
				},
				answer: []testResult{
					testResult{
						name:  "ns1-2.akam.net.",
						qtype: "A",
						value: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
					},
				},
			},

			testRecord{
				query: testQuery{
					name:  "mxa-00271601.gslb.pphosted.com.",
					qtype: "A",
				},
				answer: []testResult{
					testResult{
						name:  "mxa-00271601.gslb.pphosted.com.",
						qtype: "A",
						//value: "62.209.51.218",
						value: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
					},
				},
			},*/

		/*
			testRecord{
				query: testQuery{
					name:  "124.226.141.202.in-addr.arpa",
					qtype: "PTR",
					debug: true,
				},
				answer: []testResult{
					testResult{
						name:  "124.226.141.202.in-addr.arpa.",
						qtype: "PTR",
						value: "202-141-226-124.multi.net.pk.",
					},
				},*/
	}

	/*
		testRecord{
			query: testQuery{
				name:  "ocsp.int-x3.letsencrypt.org.edgesuite.net.",
				qtype: "A",
				debug: false,
			},
			answer: []testResult{
				testResult{
					name:  "ocsp.int-x3.letsencrypt.org.edgesuite.net.",
					qtype: "CNAME",
					value: ".*.akamai.net.",
				},
				testResult{
					name:  "a771.dscq.akamai.net.",
					qtype: "A",
					//value: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.d{1,3}",
					value: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.226",
				},
			},
		},*/

	// mxa-00271601.gslb.pphosted.com.

	/*
		testRecord{
			query: testQuery{
				name:  "example.com",
				qtype: "A",
			},
			answer: []testResult{
				testResult{
					name:  "example.com.",
					qtype: "A",
					value: "93.184.216.34",
				},
			},
		},
	*/
	//}

	resolver := New()

	t.Run("testResolving", func(t *testing.T) {
		for _, record := range records {
			// execute valid requests
			t.Run(fmt.Sprintf("testResolving/%s_%s", record.query.name, record.query.qtype), func(t *testing.T) {
				if record.query.debug {
					resolver.Debug(true)
				}
				resolver.testResolving(t, record)
				resolver.Debug(false)
			})
		}
	})

	time.Sleep(1 * time.Second)
}

func (r *Resolver) testResolving(t *testing.T, record testRecord) {
	rrs, err := r.Resolve(record.query.name, record.query.qtype)
	if r.debug {
		log.Printf("rr: %+v err:%s", rrs, err)
	}

	assert.Nil(t, err)
	if rrs == nil {
		assert.FailNow(t, "failed to resolve")
	}

	for _, result := range record.answer {
		ok := 0
		for _, rr := range rrs.Answer {
			//r, err := regexp.Compile(fmt.Sprintf("/%s\\t\\d+.*%s.*%s/", result.name, result.qtype, result.value))
			r, err := regexp.Compile(fmt.Sprintf("^%s\\t+\\d+.*%s\\t+%s", result.name, result.qtype, result.value))
			log.Printf("matching [%s] with [%s]\n", rr.String(), fmt.Sprintf("^%s\\t+\\d+.*%s\\t+%s", result.name, result.qtype, result.value))
			assert.Nil(t, err)
			//if rr.String()
			if r.MatchString(rr.String()) {
				ok++
			}
		}
		assert.Equal(t, 1, ok, "answer record: %v expected: %v", result, fmt.Sprintf("^%s\\t+\\d+.*%s\\t+%s", result.name, result.qtype, result.value))
		log.Printf("rrs: %+v", rrs)
	}

	for _, result := range record.ns {
		ok := 0
		for _, rr := range rrs.Ns {
			//r, err := regexp.Compile(fmt.Sprintf("/%s\\t\\d+.*%s.*%s/", result.name, result.qtype, result.value))
			//r, err := regexp.Compile(fmt.Sprintf("^%s\\t+\\d+.*%s\\s+%s", result.name, result.qtype, result.value))
			r, err := regexp.Compile(fmt.Sprintf("^%s\\t+.*%s\\s+%s", result.name, result.qtype, result.value))
			log.Printf("matching [%s] with [%s]\n", rr.String(), fmt.Sprintf("^%s\\t+.*%s\\t+%s", result.name, result.qtype, result.value))
			assert.Nil(t, err)
			//if rr.String()
			if r.MatchString(rr.String()) {
				ok++
			}
		}
		assert.Equal(t, 1, ok, "ns record: %v expected: %v", result, fmt.Sprintf("^%s\\t+\\d+.*%s\\t+%s", result.name, result.qtype, result.value))
	}

	for _, result := range record.extra {
		ok := 0
		for _, rr := range rrs.Extra {
			r, err := regexp.Compile(fmt.Sprintf("^%s\\t+\\d+.*%s\\s+%s", result.name, result.qtype, result.value))
			log.Printf("matching [%s] with [%s]\n", rr.String(), fmt.Sprintf("^%s\\t+\\d+.*%s\\t+%s", result.name, result.qtype, result.value))
			assert.Nil(t, err)
			//if rr.String()
			if r.MatchString(rr.String()) {
				ok++
			}
		}
		assert.Equal(t, 1, ok, "extra record: %v expected: %v", result, fmt.Sprintf("^%s\\t+\\d+.*%s\\t+%s", result.name, result.qtype, result.value))
	}

}

/*
func TestSimple(t *testing.T) {
	resolver := New()
	resolver.Debug(true)
	r, e := resolver.querySingle(context.Background(), "199.249.112.1", "ghostbox.org.", "ns", map[string]int{}, 1)
	log.Printf("r:%+v e:%s", r.Answer, e)
}
*/
