package tinyresolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sort"
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
	debug   bool
	m       sync.RWMutex
}

// New creates a new resolver
func New() *Resolver {
	return &Resolver{
		timeout: Timeout,
		cache:   newCache(),
		debug:   false,
	}
}

// Debug enables or disables debug logging of a query
func (r *Resolver) Debug(enable bool) {
	r.m.Lock()
	defer r.m.Unlock()
	r.debug = enable
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
	if r.debug {
		log.Printf("INITIAL %d query - %s %s", depth, qname, qtype)
	}
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
	if r.debug {
		log.Printf("\n----------- QUERY WITH CACHE depth:%d - [%s] [%s] ---------\n", depth, qname, qtype)
	}
	if depth > MaxDepth {
		return nil, ErrMaxDepth
	}
	// find requested record in cache
	msg := r.cache.get(qname, qtype)
	if len(msg.Answer) != 0 {
		if r.debug {
			log.Printf("CACHED result depth:%d [%s] [%s] returns: \n%+v\n", depth, qname, qtype, msg)
		}
		return msg, nil
	}

	qloc.Lock()
	if _, ok := qs[qname+"_"+qtype]; ok {
		qs[qname+"_"+qtype]++
		if qs[qname+"_"+qtype] > 4 {
			qloc.Unlock()
			return nil, ErrQueryLoop
		}
	} else {
		qs[qname+"_"+qtype] = 1
	}
	qloc.Unlock()
	// if record is not in cache, find the NS for the record in cache
	// find requested record in cache
	//log.Printf("QUERY NS depth:%d - %s %s", depth, qname, qtype)
	msg = r.cache.get(qname, "NS")
	if len(msg.Answer) != 0 {
		//log.Printf("CACHED NS result depth:%d", depth)
	} else {
		//log.Printf("NONCACHED depth:%d - %s %s: %+v", depth, qname, qtype, msg)
	}

	nsrrs := msg.Answer
	if len(nsrrs) == 0 {
		///log.Printf("QUERY NS records for query not found, check upstream depth:%d - %s %s", depth, qname, "NS")
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
			///log.Printf("QUERY NS records for query not returned???, failed to find in upstream depth:%d - %s %s", depth, qname, "NS")
			nsrrs = msg.Ns
		} else {
			///log.Printf("QUERY NS records for query returned, OK in upstream depth:%d - %s %s", depth, qname, "NS")
			nsrrs = msg.Answer
		}

	}

	//log.Printf("RESULT NS %d records for query: %s %s %+v", depth, qname, "NS", nsrrs)
	// we should have NS records now to do the query

	ns := findNS(nsrrs)
	if len(ns) == 0 {
		//log.Printf("FINAL NS depth:%d error findDNS %s", depth, ErrNoNS)
		return nil, ErrNoNS
	}
	///log.Printf("QUERY depth:%d returned the folling NS - \n%+v\n", depth, ns)

	// if not in cache, find record on available NS's
	///log.Printf("QUERY depth:%d on multiple NS's - %s %s", depth, qname, qtype)
	rmsg, err := r.queryMultiple(ctx, ns, qname, qtype, qs, depth+1)
	if err != nil {
		///log.Printf("QUERY %d multiple failed: %s %s -> %s", depth, qname, qtype, err)
		return nil, err
	}

	///log.Printf("FINISHED %d query - %s %s\nmsg: %v\n", depth, qname, qtype, msg)
	for qtype == "A" && len(findA(rmsg.Answer)) == 0 && depth < MaxDepth {
		cname := findCNAME(rmsg.Answer)
		if len(cname) == 0 {
			break
		}
		depth++
		// follow the latest cname added
		msg2, err := r.queryWithCache(ctx, cname[len(cname)-1], "A", depth, qs)
		if err == nil {
			rmsg.Answer = append(rmsg.Answer, msg2.Answer...)
		}
	}

	//log.Printf("QUERY %d multiple ok!: %s %s -> %s", depth, qname, qtype, err)

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
			///log.Printf("QUERY  MULTIPLE initiated on depth:%d for [%s] [%s] on %s", depth, qname, qtype, ns)
			r.querySingleChan(ctx2, nsq, qname, qtype, qa, qs, depth)
		}()
	}

	for {
		select {
		case answer := <-qa:
			count--
			// if we have a valid response or we ran out of servers to query, return the resolt
			if answer.err == nil || count == 0 {
				if r.debug {
					log.Printf("QUERY MULTIPLE RESULT depth:%d: %s %s @%s err:%s\n msg:%+v", depth, qname, qtype, answer.server, answer.err, answer.msg)
				}
				return answer.msg, answer.err
			}
		case <-ctx.Done():
			if r.debug {
				log.Printf("QUERY MULTIPLE CTX %d: %s %s", depth, qname, qtype)
			}
			return nil, ctx.Err()
		}
	}
}

func (r *Resolver) querySingleChan(ctx context.Context, ns string, qname, qtype string, answer chan queryAnswer, qs map[string]int, depth int) {
	/*defer func() {
		if recover() != nil {
			return
		}
	}()*/

	///log.Printf("depth:%d single query start ns:%s qname:%s qtype:%s", depth, ns, qname, qtype)
	//defer log.Printf("single query end ns:%s qname:%s qtype:%s", ns, qname, qtype)
	msg, err := r.querySingle(ctx, ns, qname, qtype, qs, depth)

	///log.Printf("depth:%d single query end with ns:%s qname:%s qtype:%s result:\n%+v\nerr: %s\n", depth, ns, qname, qtype, msg, err)
	//if qtype == "NS" && len(msg.answer rdoorn

	//log.Printf("single query reply: %+v", msg)
	if qtype == "NS" && msg.Extra == nil {
		msg.Extra = []dns.RR{}
	}
	if qtype == "NS" && len(findA(msg.Answer)) == 0 && len(findA(msg.Extra)) == 0 {
		///log.Printf("depth:%d got NS servers, but no A records, querying seperately", depth)
		for _, qns := range findNS(msg.Answer) {
			///log.Printf("depth:%d find NS from answer: %s", depth, qns)
			msg2, err2 := r.querySingle(ctx, ns, qns, "A", qs, depth)
			///log.Printf("depth:%d find NS result: %+v, %s", depth, msg2, err2)
			if err2 == nil {
				msg.Extra = append(msg.Extra, msg2.Answer...)
			}
		}
	}

	if qtype == "NS" && len(findA(msg.Answer)) != len(findA(msg.Extra)) {

		foundNS := findNameOfA(msg.Extra)

		remove := []int{}
		// go through answers
		for aid, a := range msg.Answer {
			if a.Header().Rrtype == dns.TypeNS {
				// go through ip's in extras
				found := false
				for _, f := range foundNS {
					///log.Printf("checking if [%s] contains [%s]", a.String(), f)
					if strings.Contains(a.String(), f) {
						found = true
					}
				}

				if !found {
					remove = append(remove, aid)
				}
			}
		}
		sort.Sort(sort.Reverse(sort.IntSlice(remove)))
		for _, s := range remove {
			msg.Answer = append(msg.Answer[:s], msg.Answer[s+1:]...)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		select {
		case <-ctx.Done():
			return

		//log.Printf("QUERY SINGLE %d: %s %s @%s returned result", depth, qname, qtype, ns)
		case answer <- queryAnswer{
			msg:    msg,
			err:    err,
			server: ns,
		}:
			//log.Printf("QUERY SINGLE FIN ANSWER %d: %s %s @%s returned result", depth, qname, qtype, ns)
			return
		}
	}
}

//func (r *Resolver) querySingle(ctx context.Context, ns string, qname, qtype string) (*dns.Msg, error) {
func (r *Resolver) querySingle(ctx context.Context, ns string, qname, qtype string, qs map[string]int, depth int) (*dns.Msg, error) {

	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	qmsg := &dns.Msg{}
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false
	if qtype == "NS" {
		qmsg.MsgHdr.RecursionDesired = true
	}

	ip := ""
	if !IsIpv4Net(ns) {
		///log.Printf("Finding A record for NS server depth:%d ns:%s\n", depth, ns)
		nsa, err := r.queryWithCache(ctx, ns, "A", depth+1, qs)
		if err != nil {
			return nil, err
		}
		nsip := findA(nsa.Answer)
		if len(nsip) == 0 {
			return nil, fmt.Errorf("failed to get A record for %s", ns)
		}

		ip = nsip[0]
	} else {
		ip = ns
	}

	client := &dns.Client{Timeout: r.timeout} // client must finish within remaining timeout
	///log.Printf("depth:%d executing query on %s, msg:%+v\n", depth, ip, qmsg)
	rmsg, _, err := client.ExchangeContext(ctx, qmsg, ip+":53")
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

func findNameOfA(rrs []dns.RR) (res []string) {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeA {
			ip := strings.Split(rr.String(), "\t")[0]
			/*ipp := net.ParseIP(ip)
			if ipp.To4() == nil {*/
			res = append(res, ip)
			//}
		}
	}
	return
}

func IsIpv4Net(host string) bool {
	return net.ParseIP(host) != nil
}
