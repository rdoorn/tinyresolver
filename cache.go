package tinyresolver

import (
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type rrDetails struct {
	rr      dns.RR
	expires time.Time
}

type cache struct {
	rrs []rrDetails
}

// newCache creates a new cache pool
func newCache() *cache {
	c := &cache{}
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error != nil {
			continue
		}
		c.addRR(t.RR)
	}
	return c
}

// addMsg adds all entries in a message to the cache
func (c *cache) addMsg(rmsg *dns.Msg) {
	if rmsg == nil {
		return
	}
	for _, rr := range rmsg.Ns {
		c.addRR(rr)
	}
	for _, rr := range rmsg.Answer {
		c.addRR(rr)
	}
	for _, rr := range rmsg.Extra {
		c.addRR(rr)
	}
}

// addRR adds a single record to the cache
func (c *cache) addRR(rr dns.RR) {
	rr.Header().Name = toLowerFQDN(rr.Header().Name)
	switch rr.(type) {
	case *dns.NS:
		rr.(*dns.NS).Ns = toLowerFQDN(rr.(*dns.NS).Ns)
	}
	for id, cachedrr := range c.rrs {
		// get record without TTL
		newRR := removeSliceString(strings.Split(rr.String(), "\t"), 1)
		cachedRR := removeSliceString(strings.Split(cachedrr.rr.String(), "\t"), 1)
		if reflect.DeepEqual(newRR, cachedRR) {
			// record already exists
			newExpire := time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second)
			if newExpire.After(cachedrr.expires) {
				c.rrs[id].expires = newExpire
			}
			return
		}
	}
	rrDetail := rrDetails{
		rr:      rr,
		expires: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
	}
	log.Printf("cache adding: %+v", rr)
	c.rrs = append(c.rrs, rrDetail)
}

// get retreives a query from the cache
func (c *cache) get(qname, qtype string) *dns.Msg {
	msg := &dns.Msg{}

	now := time.Now()
	qname = toLowerFQDN(qname)
	dtype := dns.StringToType[qtype]
	for _, rr := range c.rrs {
		if rr.rr.Header().Rrtype == dtype && rr.rr.Header().Name == qname && now.Before(rr.expires) {

			//log.Printf("expires: %v + in seconds = %v", rr.expires, rr.expires.Sub(now)/time.Second)
			rr.rr.Header().Ttl = uint32(rr.expires.Sub(now) / time.Second)
			msg.Answer = append(msg.Answer, rr.rr)
		}
	}
	if len(msg.Answer) == 0 {
		return msg
	}

	switch qtype {
	case "MX":
		mxs := findMX(msg.Answer)
		for _, mx := range mxs {
			t := c.get(mx, "A")
			msg.Extra = append(msg.Extra, t.Answer...)
		}
	case "NS":
		nss := findNS(msg.Answer)
		for _, ns := range nss {
			t := c.get(ns, "A")
			msg.Extra = append(msg.Extra, t.Answer...)
		}
	case "CNAME":
		cnames := findCNAME(msg.Answer)
		for _, cname := range cnames {
			t := c.get(cname, "A")
			msg.Extra = append(msg.Extra, t.Answer...)
		}
	}

	return msg
}

// removeSliceString removes a string from a slice of strings
func removeSliceString(slice []string, s int) []string {
	return append(slice[:s], slice[s+1:]...)
}
