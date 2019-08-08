package tinyresolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {
	c := newCache()
	rmsg := &dns.Msg{}
	ip := net.ParseIP("10.10.10.10")
	rr := &dns.A{Hdr: dns.RR_Header{Name: "dns.org", Ttl: 86400, Class: dns.ClassINET, Rrtype: dns.TypeA}, A: ip}
	rmsg.Answer = append(rmsg.Answer, rr)
	time.Sleep(100 * time.Millisecond)
	c.addMsg(rmsg)
	res1 := c.get("dns.org", "A")
	assert.Equal(t, uint32(86399), res1.Answer[0].Header().Ttl)
	time.Sleep(1 * time.Second)
	res1 = c.get("dns.org", "A")
	assert.Equal(t, uint32(86398), res1.Answer[0].Header().Ttl)
}
