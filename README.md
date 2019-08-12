# tinyresolver

tiny resolver is a simple DNS resolver for Golang, it can be used instead of a external DNS server as it relies on root hits to do its queries

usage:

```
resolver := tinyresolver.New()
rr, err := resolver.Resolve("ghostbox.org", "A")
if err != nil {
  panic(err)
}

answer := rr.Extra[0]
log.Printf("IP: %s", answer.(*dns.A).A)
```

it uses the miekg dns library, and these are also the results it returns. 
