package tinyresolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	Timeout        = 2 * time.Second // timeout for the entire request
	MaxDepth       = 20              // max recursive depth to query
	MaxNameservers = 4               // max name servers to query simultainiously
)

var (
	ErrMaxDepth  = errors.New("Max recursion depth reached")
	ErrMaxParent = errors.New("Max parent reached")
	ErrNoNS      = errors.New("no NS record found for domain")
)

type Resolver struct {
	timeout time.Duration
	cache   *cache
}

func New() *Resolver {
	return &Resolver{
		timeout: Timeout,
		cache:   newCache(),
	}
}

// Resolve resolves a query, and returns all results
func (r *Resolver) Resolve(qname, qtype string) (*dns.Msg, error) {
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return r.resolveWithContext(ctx, toLowerFQDN(qname), qtype, 0)
}

// resolveWithContext resolves a query, and returns all results, with a context handler
func (r *Resolver) resolveWithContext(ctx context.Context, qname, qtype string, depth int) (*dns.Msg, error) {
	msg, err := r.queryWithCache(ctx, qname, qtype, depth)
	if qtype == "A" && len(findA(msg.Answer)) == 0 {
		cname := findCNAME(msg.Answer)
		if len(cname) > 0 {
			msg2, err := r.queryWithCache(ctx, cname[0], "A", depth)
			if err == nil {
				msg.Answer = append(msg.Answer, msg2.Answer...)
			}
		}
	}
	return msg, err
}

// queryWithCache
func (r *Resolver) queryWithCache(ctx context.Context, qname, qtype string, depth int) (*dns.Msg, error) {
	log.Printf("query %d - %s %s", depth, qname, qtype)
	if depth > MaxDepth {
		return nil, ErrMaxDepth
	}

	// find requested record in cache
	msg := r.cache.get(qname, qtype)
	if len(msg.Answer) != 0 {
		log.Printf("query %d done cache", depth)
		return msg, nil
	}

	// if record is not in cache, find the NS for the record in cache
	// find requested record in cache
	msg = r.cache.get(qname, "NS")
	nsrrs := msg.Answer
	if len(nsrrs) == 0 {
		// if record is not in cache, ask for the parent NS
		pname, ok := parent(qname)
		if !ok {
			log.Printf("query %d done %s", depth, ErrMaxParent)
			return nil, ErrMaxParent
		}
		var err error
		msg, err := r.queryWithCache(ctx, pname, "NS", depth+1)
		log.Printf("query %d done query parent %s %s %s %+v", depth, pname, "NS", err, nsrrs)
		if err != nil {
			return nil, ErrNoNS
		}
		log.Printf("qwc := %+v", msg)
		if len(msg.Answer) == 0 {
			nsrrs = msg.Ns
		} else {
			nsrrs = msg.Answer
		}

	}

	log.Printf("query %d NS records for query: %s %s %+v", depth, qname, "NS", nsrrs)
	// we should have NS records now to do the query

	ns := findNS(nsrrs)
	if len(ns) == 0 {
		log.Printf("query %d done findDNS %s", depth, ErrNoNS)
		return nil, ErrNoNS
	}

	// if not in cache, find record on available NS's
	rmsg, err := r.queryMultiple(ctx, ns, qname, qtype)

	if err != nil {
		log.Printf("query %d done %s", depth, err)
		return nil, err
	}

	// add record to cache
	r.cache.addMsg(rmsg)

	log.Printf("query %d message: %s %s %+v", depth, qname, qtype, rmsg)

	return rmsg, nil
}

func (r *Resolver) queryMultiple(ctx context.Context, ns []string, qname, qtype string) (*dns.Msg, error) {
	m := make(chan dns.Msg)
	e := make(chan error)
	ctx2, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	count := 0
	for i := 0; i < MaxNameservers && i < len(ns); i++ {
		count++
		nsq := ns[i]
		go func() {
			msg, err := r.querySingle(ctx2, nsq, qname, qtype)
			m <- *msg
			e <- err
		}()
	}
	for {
		select {
		case msg := <-m:
			err := <-e
			count--
			if err == nil && (len(msg.Ns) > 0 || len(msg.Answer) > 0) {
				return &msg, err
			}
			if count == 0 {
				return &msg, err
			}
		case <-ctx2.Done():
			log.Printf("ctx2 got canceled: %s", ctx2.Err())
			return nil, ctx2.Err()
		}
	}
}

func (r *Resolver) querySingle(ctx context.Context, ns string, qname, qtype string) (*dns.Msg, error) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	qmsg := &dns.Msg{}
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false

	nsa, _ := r.queryWithCache(ctx, ns, "A", 1)
	nsip := findA(nsa.Answer)
	if len(nsip) == 0 {
		return nil, fmt.Errorf("failed to get A record for %s", ns)
	}

	// Synchronously query this DNS server
	start := time.Now()
	timeout := r.timeout // belt and suspenders, since ctx has a deadline from ResolveErr
	if dl, ok := ctx.Deadline(); ok {
		timeout = dl.Sub(start)
	}

	log.Printf("doing a remote query on %s for %s %s", nsip[0], qname, qtype)
	client := &dns.Client{Timeout: timeout} // client must finish within remaining timeout
	rmsg, dur, err := client.ExchangeContext(ctx, qmsg, nsip[0]+":53")
	log.Printf("got result: %+v dur:%v err:%s", rmsg, dur, err)

	return rmsg, nil
}

func parent(name string) (string, bool) {
	labels := dns.SplitDomainName(name)
	if labels == nil {
		return "", false
	}
	return toLowerFQDN(strings.Join(labels[1:], ".")), true
}

func toLowerFQDN(name string) string {
	return dns.Fqdn(strings.ToLower(name))
}

func findNS(rrs []dns.RR) (res []string) {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeNS {
			res = append(res, strings.Split(rr.String(), "\t")[4])
		}
		if rr.Header().Rrtype == dns.TypeSOA {
			soa := strings.Split(rr.String(), "\t")[4]
			host := strings.Split(soa, " ")[1]
			res = append(res, host)
		}
	}
	return
}

func findMX(rrs []dns.RR) (res []string) {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeMX {
			value := strings.Split(rr.String(), "\t")[4]
			res = append(res, strings.Split(value, " ")[1])
		}
	}
	return
}

func findA(rrs []dns.RR) (res []string) {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeA {
			ip := strings.Split(rr.String(), "\t")[4]
			/*ipp := net.ParseIP(ip)
			if ipp.To4() == nil {*/
			res = append(res, ip)
			//}
		}
	}
	return
}

func findCNAME(rrs []dns.RR) (res []string) {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeCNAME {
			ip := strings.Split(rr.String(), "\t")[4]
			/*ipp := net.ParseIP(ip)
			if ipp.To4() == nil {*/
			res = append(res, ip)
			//}
		}
	}
	return
}
