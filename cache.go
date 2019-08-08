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
	rrs []dns.RR
}

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

func (c *cache) addMsg(rmsg *dns.Msg) {
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

func (c *cache) addRR(rr dns.RR) {
	log.Printf("cache adding: %+v", rr)
	for id, cachedrr := range c.rrs {
		/*now := time.Now()
		expires := now.Add(time.Duration(rr.Header().Ttl) * time.Second)
		rr.Header().Ttl = int64(expires / time.Second)*/

		// get record without TTL
		newRR := removeSliceString(strings.Split(rr.String(), "\t"), 1)
		cachedRR := removeSliceString(strings.Split(cachedrr.String(), "\t"), 1)
		if reflect.DeepEqual(newRR, cachedRR) {
			// record already exists
			// if cached TTL > new TTL ,do nothing
			if cachedrr.Header().Ttl > rr.Header().Ttl {
				return
			}

			// if newTTL > cached TTL, update TTL
			c.rrs[id].Header().Ttl = rr.Header().Ttl
			return
		}
	}
	c.rrs = append(c.rrs, rr)
}

func (c *cache) get(qname, qtype string) *dns.Msg {
	msg := &dns.Msg{}

	dtype := dns.StringToType[qtype]
	for _, rr := range c.rrs {
		if rr.Header().Rrtype == dtype {
			if rr.Header().Name == qname {
				msg.Answer = append(msg.Answer, rr)
			}
		}
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
	/*if len(rrs) > 0 {
		log.Printf("returning cached RRs: %+v", rrs)
	}*/

	//msg.Answer = rrs
	return msg
}

func removeSliceString(slice []string, s int) []string {
	return append(slice[:s], slice[s+1:]...)
}
