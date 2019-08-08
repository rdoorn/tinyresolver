package tinyresolver

import (
	"log"
	"strings"

	"github.com/miekg/dns"
)

type cache struct {
	rrs []dns.RR
}

func newCache() *cache {
	c := &cache{}
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error != nil {
			continue
		}
		c.add(t.RR)
	}
	return c
}

func (c *cache) add(rr dns.RR) {
	log.Printf("cache adding: %+v", rr)
	c.rrs = append(c.rrs, rr)
}

func (c *cache) get(qname, qtype string) (rrs []dns.RR) {
	dtype := dns.StringToType[qtype]
	for _, rr := range c.rrs {
		if rr.Header().Rrtype == dtype {
			if rr.Header().Name == qname {
				rrs = append(rrs, rr)
			}
		}
	}
	if len(rrs) > 0 {
		log.Printf("returning cached RRs: %+v", rrs)
	}
	return
}
