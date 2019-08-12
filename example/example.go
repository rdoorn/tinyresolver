package main

import (
	"log"

	"github.com/miekg/dns"
	"github.com/rdoorn/tinyresolver"
)

func main() {

	resolver := tinyresolver.New()
	rr, err := resolver.Resolve("ghostbox.org", "A")
	if err != nil {
		panic(err)
	}

	answer := rr.Extra[0]
	log.Printf("IP: %s", answer.(*dns.A).A)
}
