package ipsource

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
)

// Owner is the origin AS of an address and the prefix it is announced in.
type Owner struct {
	ASN    int
	Prefix string
}

// Origin asks Team Cymru's origin zone, through the public resolvers, which AS
// announces the address. found is false when Cymru knows nothing of it: an
// NXDOMAIN, or an answer with no origin that can be read. A transport failure
// or a resolver answering anything but success or NXDOMAIN is an error.
func Origin(ctx context.Context, r egress.Resolver, addr netip.Addr) (Owner, bool, error) {
	res, err := r.Query(ctx, dnsname.CymruOrigin(addr), egress.TypeTXT)
	if err != nil {
		return Owner{}, false, err
	}
	switch res.RCode {
	case egress.RCodeSuccess:
	case egress.RCodeNXDomain:
		return Owner{}, false, nil
	default:
		return Owner{}, false, fmt.Errorf("resolver answered rcode %d", res.RCode)
	}
	for _, a := range res.Answers {
		if a.Type != "TXT" {
			continue
		}
		f := fields(a.Value)
		// "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"; with several origins, take the first.
		if len(f) >= 2 {
			first, _, _ := strings.Cut(f[0], " ")
			if n, err := strconv.Atoi(first); err == nil {
				// The first answer that reads is the origin; AS0 names none.
				if n == 0 {
					return Owner{}, false, nil
				}
				return Owner{ASN: n, Prefix: f[1]}, true, nil
			}
		}
	}
	return Owner{}, false, nil
}

// ASName asks Team Cymru for the holder of an AS, without the ", CC" country
// suffix it appends. An AS Cymru does not know (NXDOMAIN), or an answer with no
// name, gives "" and no error.
func ASName(ctx context.Context, r egress.Resolver, asn int) (string, error) {
	res, err := r.Query(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asn), egress.TypeTXT)
	if err != nil {
		return "", err
	}
	if res.RCode != egress.RCodeSuccess && res.RCode != egress.RCodeNXDomain {
		return "", fmt.Errorf("resolver answered rcode %d for AS%d", res.RCode, asn)
	}
	for _, a := range res.Answers {
		// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
		if f := fields(a.Value); a.Type == "TXT" && len(f) >= 5 {
			return trimCountry(f[4]), nil
		}
	}
	return "", nil
}

func fields(txt string) []string {
	parts := strings.Split(txt, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// trimCountry drops the ", US" country suffix Team Cymru appends to the holder.
func trimCountry(h string) string {
	if i := strings.LastIndex(h, ", "); i > 0 && len(h)-i == 4 {
		return h[:i]
	}
	return h
}
