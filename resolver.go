package tinyresolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// Timeout is the time in seconds the request is allowed to take before a timeout error is returned
	Timeout = 4 * time.Second

	// MaxDepth is the max recursive depth to query
	MaxDepth = 10

	// MaxNameservers is the max name servers to query simultainiously
	MaxNameservers = 4
)

// Various errors
var (
	ErrMaxDepth  = errors.New("Max recursion depth reached")
	ErrMaxParent = errors.New("Max parent reached")
	ErrNoNS      = errors.New("no NS record found for domain")
	ErrQueryLoop = errors.New("loop in query")
)

// Resolver is the resolver object
type Resolver struct {
	timeout time.Duration
	cache   *cache
}

// New creates a new resolver
func New() *Resolver {
	return &Resolver{
		timeout: Timeout,
		cache:   newCache(),
	}
}

// Resolve resoves a record by name and type, and returns the message of the answer
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
	qs := make(map[string]int)
	//log.Printf("INITIAL %d query - %s %s", depth, qname, qtype)
	//qs[qname+qtype] = true
	msg, err := r.queryWithCache(ctx, qname, qtype, depth, qs)
	if err != nil {
		return nil, err
	}
	for len(msg.Answer) == 0 && depth < MaxDepth && err != ErrQueryLoop {
		depth++
		msg2, err2 := r.queryWithCache(ctx, qname, qtype, depth, qs)
		if err2 == nil {
			msg.Answer = append(msg.Answer, msg2.Answer...)
			//return nil, err
		}
	}
	//log.Printf("FINISHED %d query - %s %s\nmsg: %v\n", depth, qname, qtype, msg)
	for qtype == "A" && len(findA(msg.Answer)) == 0 && depth < MaxDepth {
		cname := findCNAME(msg.Answer)
		if len(cname) == 0 {
			break
		}
		depth++
		// follow the latest cname added
		msg2, err := r.queryWithCache(ctx, cname[len(cname)-1], "A", depth, qs)
		if err == nil {
			msg.Answer = append(msg.Answer, msg2.Answer...)
		}
	}
	if qtype == "NS" && len(findA(msg.Extra)) == 0 {
		ns := findNS(msg.Answer)
		if len(ns) > 0 {
			msg2, err := r.queryWithCache(ctx, ns[0], "A", depth, qs)
			if err == nil {
				msg.Extra = append(msg.Extra, msg2.Extra...)
			}
		}
	}
	return msg, err
}

var qloc sync.Mutex

// queryWithCache
func (r *Resolver) queryWithCache(ctx context.Context, qname, qtype string, depth int, qs map[string]int) (*dns.Msg, error) {
	//log.Printf("QUERY WITH CACHE %d - %s %s", depth, qname, qtype)
	if depth > MaxDepth {
		return nil, ErrMaxDepth
	}
	// find requested record in cache
	msg := r.cache.get(qname, qtype)
	if len(msg.Answer) != 0 {
		//log.Printf("CACHED result %d", depth)
		return msg, nil
	}

	qloc.Lock()
	if _, ok := qs[qname+"_"+qtype]; ok {
		qs[qname+"_"+qtype]++
		if qs[qname+"_"+qtype] > 2 {
			qloc.Unlock()
			return nil, ErrQueryLoop
		}
	} else {
		qs[qname+"_"+qtype] = 1
	}
	qloc.Unlock()
	// if record is not in cache, find the NS for the record in cache
	// find requested record in cache
	//log.Printf("QUERY NS %d - %s %s", depth, qname, qtype)
	msg = r.cache.get(qname, "NS")
	if len(msg.Answer) != 0 {
		//log.Printf("CACHED NS result %d", depth)
	} else {
		//log.Printf("NONCACHED %d - %s %s: %+v", depth, qname, qtype, msg)
	}

	nsrrs := msg.Answer
	if len(nsrrs) == 0 {
		// if record is not in cache, ask for the parent NS
		pname, ok := parent(qname)
		if !ok {
			//log.Printf("QUERY NS %d done %s", depth, ErrMaxParent)
			return nil, ErrMaxParent
		}
		var err error
		msg, err := r.queryWithCache(ctx, pname, "NS", depth+1, qs)
		//log.Printf("QUERY NS %d query on %s %s returned: %+v", depth, pname, "NS", msg)
		if err != nil {
			return nil, err
		}
		////log.Printf("qwc := %+v", msg)
		if len(msg.Answer) == 0 {
			nsrrs = msg.Ns
		} else {
			nsrrs = msg.Answer
		}

	}

	//log.Printf("RESULT NS %d records for query: %s %s %+v", depth, qname, "NS", nsrrs)
	// we should have NS records now to do the query

	ns := findNS(nsrrs)
	if len(ns) == 0 {
		////log.Printf("FINAL NS %d error findDNS %s", depth, ErrNoNS)
		return nil, ErrNoNS
	}

	// if not in cache, find record on available NS's
	//log.Printf("QUERY %d retry now on NS - %s %s", depth, qname, qtype)
	rmsg, err := r.queryMultiple(ctx, ns, qname, qtype, qs, depth)
	if err != nil {
		//log.Printf("QUERY %d multiple failed: %s", depth, err)
		return nil, err
	}

	// add record to cache
	r.cache.addMsg(rmsg)

	//log.Printf("QUERY %d FINAL message: %s %s %+v", depth, qname, qtype, rmsg)

	return rmsg, nil
}

type queryAnswer struct {
	msg    *dns.Msg
	err    error
	server string
}

func (r *Resolver) queryMultiple(ctx context.Context, ns []string, qname, qtype string, qs map[string]int, depth int) (*dns.Msg, error) {
	qa := make(chan queryAnswer)

	ctx2, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// shuffle NS's so we don't always query the first server
	for i := range ns {
		j := rand.Intn(i + 1)
		ns[i], ns[j] = ns[j], ns[i]
	}

	// count instances started
	count := 0
	for i := 0; i < MaxNameservers && i < len(ns); i++ {
		count++
		nsq := ns[i]
		go func() {
			r.querySingleChan(ctx2, nsq, qname, qtype, qa, qs, depth)
		}()
	}

	for {
		select {
		case answer := <-qa:
			count--
			// if we have a valid response or we ran out of servers to query, return the resolt
			if answer.err == nil || count == 0 {
				//log.Printf("QUERY MULTIPLE RESULT %d: %s %s @%s err:%s", depth, qname, qtype, answer.server, answer.err)
				return answer.msg, answer.err
			}
		case <-ctx.Done():
			//log.Printf("QUERY MULTIPLE CTX %d: %s %s", depth, qname, qtype)
			return nil, ctx.Err()
		}
	}
}

func (r *Resolver) querySingleChan(ctx context.Context, ns string, qname, qtype string, answer chan queryAnswer, qs map[string]int, depth int) {
	//log.Printf("QUERY SINGLE %d: %s %s @%s", depth, qname, qtype, ns)
	msg, err := r.querySingle(ctx, ns, qname, qtype, qs)
	for {
		select {
		case <-ctx.Done():
			//log.Printf("QUERY SINGLE FIN CTX %d: %s %s @%s returned result", depth, qname, qtype, ns)
			return
		default:

			//log.Printf("QUERY SINGLE %d: %s %s @%s returned result", depth, qname, qtype, ns)
			answer <- queryAnswer{
				msg:    msg,
				err:    err,
				server: ns,
			}
			//log.Printf("QUERY SINGLE FIN ANSWER %d: %s %s @%s returned result", depth, qname, qtype, ns)
			return
		}
	}
}

//func (r *Resolver) querySingle(ctx context.Context, ns string, qname, qtype string) (*dns.Msg, error) {
func (r *Resolver) querySingle(ctx context.Context, ns string, qname, qtype string, qs map[string]int) (*dns.Msg, error) {

	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	qmsg := &dns.Msg{}
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false

	nsa, err := r.queryWithCache(ctx, ns, "A", 1, qs)
	if err != nil {
		return nil, err
	}
	nsip := findA(nsa.Answer)
	if len(nsip) == 0 {
		return nil, fmt.Errorf("failed to get A record for %s", ns)
	}

	client := &dns.Client{Timeout: r.timeout} // client must finish within remaining timeout
	rmsg, _, err := client.ExchangeContext(ctx, qmsg, nsip[0]+":53")
	if err != nil {
		return nil, err
	}

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
			host := strings.Split(soa, " ")[0]
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
			res = append(res, ip)
		}
	}
	return
}
