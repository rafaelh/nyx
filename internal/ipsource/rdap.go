package ipsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/term/sanitize"
)

const (
	// BootstrapHost is where IANA's RDAP bootstrap files are.
	BootstrapHost = "data.iana.org"
	// maxHops is how many referrals a lookup follows.
	maxHops = 3
	// RDAPAccept is the Accept header of an RDAP request.
	RDAPAccept = "application/rdap+json, application/json"
)

var errTruncated = errors.New("response was larger than the 10 MiB limit")

// Registry is one of the five regional internet registries.
type Registry struct {
	Name, Host string
	// Base is the registry service URL from bootstrap data.
	Base string
	// Search marks registries returning allocations for organisation searches. ARIN needs
	// an entity follow-up; APNIC includes them directly. Entity-only registries are
	// skipped.
	Search bool
}

var registries = []Registry{
	{"arin", "rdap.arin.net", "https://rdap.arin.net/registry/", true},
	{"ripe", "rdap.db.ripe.net", "https://rdap.db.ripe.net/", false},
	{"apnic", "rdap.apnic.net", "https://rdap.apnic.net/", true},
	{"lacnic", "rdap.lacnic.net", "https://rdap.lacnic.net/rdap/", false},
	{"afrinic", "rdap.afrinic.net", "https://rdap.afrinic.net/rdap/", false},
}

// Registries returns the five registries, in a fixed order.
func Registries() []Registry { return slices.Clone(registries) }

// RegistryByHost is the registry whose RDAP service is at host.
func RegistryByHost(host string) (Registry, bool) {
	i := slices.IndexFunc(registries, func(r Registry) bool { return r.Host == host })
	if i < 0 {
		return Registry{}, false
	}
	return registries[i], true
}

// RDAPHosts lists IANA bootstrap and five registries for callers' source allowlists.
func RDAPHosts() []string {
	out := []string{BootstrapHost}
	for _, r := range registries {
		out = append(out, r.Host)
	}
	return out
}

// Registration is the netblock an address is registered in.
type Registration struct {
	// Start and End are the first and last addresses of the range, not IPv4-mapped.
	Start, End netip.Addr
	// Registrant is the name of the registrant entity, sanitised; "" when none is named.
	Registrant string
	// Registry is the name of the registry that answered ("arin", "ripe" ...).
	Registry string
	// Handle is the registry's handle for the range, sanitised, or "<start>-<end>" when it gave none.
	Handle string
}

// Bootstrap caches IANA's address-family registry maps across Lookup calls, including fetch
// failures. The zero value is usable and concurrent calls are safe.
type Bootstrap struct {
	v4, v6 bootCache
}

type bootCache struct {
	mu   sync.Mutex
	done bool
	file *bootFile
	err  error
}

type bootFile struct{ entries []bootEntry }

type bootEntry struct {
	prefix netip.Prefix
	url    string
}

// serviceURL chooses the registry service with the longest matching bootstrap prefix.
func (b *bootFile) serviceURL(a netip.Addr) (string, bool) {
	best, bits := "", -1
	for _, e := range b.entries {
		if e.prefix.Contains(a) && e.prefix.Bits() > bits {
			best, bits = e.url, e.prefix.Bits()
		}
	}
	return best, bits >= 0
}

func (b *Bootstrap) file(ctx context.Context, c egress.ThirdPartyHTTP, a netip.Addr) (*bootFile, error) {
	cache := &b.v6
	if a.Is4() {
		cache = &b.v4
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.done {
		cache.file, cache.err = fetchBootstrap(ctx, c, a.Is4())
		cache.done = true
	}
	return cache.file, cache.err
}

func fetchBootstrap(ctx context.Context, c egress.ThirdPartyHTTP, v4 bool) (*bootFile, error) {
	name := "ipv6.json"
	if v4 {
		name = "ipv4.json"
	}
	raw, err := get(ctx, c, BootstrapHost, "https://"+BootstrapHost+"/rdap/"+name)
	if err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", name, err)
	}
	var file struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("bootstrap %s: unreadable: %w", name, err)
	}
	b := &bootFile{}
	for _, svc := range file.Services {
		if len(svc) != 2 {
			continue
		}
		u := ""
		for _, c := range svc[1] { // the https URL, which is all the client may use
			if strings.HasPrefix(c, "https://") {
				u = c
				break
			}
		}
		for _, p := range svc[0] {
			if pfx, err := netip.ParsePrefix(p); err == nil && u != "" {
				b.entries = append(b.entries, bootEntry{pfx.Masked(), u})
			}
		}
	}
	return b, nil
}

// get requires a complete 200 response. A 429 becomes RateLimitedError for the host; other
// statuses and truncated bodies are errors.
func get(ctx context.Context, c egress.ThirdPartyHTTP, host, u string) ([]byte, error) {
	resp, err := c.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: u, Accept: RDAPAccept})
	switch {
	case err != nil:
		return nil, err
	case resp.Status == 429:
		return nil, &RateLimitedError{Host: host}
	case resp.Status != 200:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	case resp.Truncated:
		return nil, errTruncated
	}
	return resp.Body, nil
}

// Lookup selects the registry through IANA bootstrap and follows up to three approved registry
// referrals. Missing allocations, 404s and unusable answers return found=false; referral/range
// problems also call warn when supplied. Rate limits return a host-specific RateLimitedError;
// other request failures return errors.
func Lookup(ctx context.Context, c egress.ThirdPartyHTTP, b *Bootstrap, addr netip.Addr, warn func(string)) (reg Registration, found bool, err error) {
	if warn == nil {
		warn = func(string) {}
	}
	if b == nil {
		b = &Bootstrap{}
	}
	file, err := b.file(ctx, c, addr)
	if err != nil {
		return Registration{}, false, err
	}
	base, ok := file.serviceURL(addr)
	if !ok {
		return Registration{}, false, nil // no registry holds it: nothing to record
	}
	raw, registry, err := follow(ctx, c, addr, base+"ip/"+addr.String(), warn)
	if err != nil || raw == nil {
		return Registration{}, false, err
	}
	var ans struct {
		Handle       string   `json:"handle"`
		StartAddress string   `json:"startAddress"`
		EndAddress   string   `json:"endAddress"`
		Entities     []Entity `json:"entities"`
	}
	if err := json.Unmarshal(raw, &ans); err != nil {
		return Registration{}, false, fmt.Errorf("unreadable response: %w", err)
	}
	start, e1 := netip.ParseAddr(ans.StartAddress)
	end, e2 := netip.ParseAddr(ans.EndAddress)
	start, end = start.Unmap(), end.Unmap()
	// Reject ranges that cannot describe the queried address; caching them would
	// misclassify later addresses.
	a := addr.Unmap()
	if e1 != nil || e2 != nil || start.Is4() != end.Is4() || a.Compare(start) < 0 || a.Compare(end) > 0 {
		warn(fmt.Sprintf("rdap: %s (%s) gave no address range for %s", registry.Name, registry.Host, addr))
		return Registration{}, false, nil //nolint:nilerr // a range that cannot be used is warned about and records no registration
	}
	registrant := ""
	for _, ent := range ans.Entities {
		if !ent.Is("registrant") {
			continue
		}
		if n := ent.Name(); n != "" {
			registrant = n
			break
		}
	}
	handle := strings.TrimSpace(sanitize.Text(ans.Handle))
	if handle == "" {
		handle = start.String() + "-" + end.String()
	}
	return Registration{Start: start, End: end, Registrant: registrant, Registry: registry.Name, Handle: handle}, true, nil
}

// follow handles up to maxHops referrals among the five registries. A 404, unapproved host or
// excess referrals completes with nil body; otherwise it returns data and the responding
// registry.
func follow(ctx context.Context, c egress.ThirdPartyHTTP, addr netip.Addr, u string, warn func(string)) ([]byte, Registry, error) {
	for hop := 0; ; hop++ {
		host := ""
		parsed, perr := url.Parse(u)
		if perr == nil {
			host = strings.ToLower(parsed.Hostname())
		}
		reg, found := RegistryByHost(host)
		if !found {
			warn(fmt.Sprintf("rdap: %s is held by %s, which is not one of the registries; no registration is recorded", addr, host))
			return nil, reg, nil
		}
		resp, err := c.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: u, Accept: RDAPAccept})
		switch {
		case err != nil:
			return nil, reg, err
		case resp.Status == 429:
			return nil, reg, &RateLimitedError{Host: reg.Host}
		case resp.Truncated:
			return nil, reg, errTruncated
		}
		switch resp.Status {
		case 200:
			return resp.Body, reg, nil
		case 404:
			return nil, reg, nil
		case 301, 302, 303, 307, 308:
		default:
			return nil, reg, fmt.Errorf("HTTP %d", resp.Status)
		}
		if hop == maxHops {
			warn(fmt.Sprintf("rdap: the lookup of %s was referred more than %d times; no registration is recorded", addr, maxHops))
			return nil, reg, nil
		}
		loc := resp.HeaderValue("Location")
		next, err := parsed.Parse(loc)
		if err != nil || loc == "" || next.Scheme != "https" {
			warn(fmt.Sprintf("rdap: %s referred the lookup of %s to %q, which cannot be followed; no registration is recorded", reg.Host, addr, loc))
			return nil, reg, nil //nolint:nilerr // a referral that cannot be followed is warned about and records no registration
		}
		u = next.String()
	}
}

// Entity retains only registrant roles and vCard data from RDAP.
type Entity struct {
	Roles []string        `json:"roles"`
	VCard json.RawMessage `json:"vcardArray"`
}

// Is reports whether the entity has the role.
func (e Entity) Is(role string) bool { return slices.Contains(e.Roles, role) }

// Name is the cleaned vCard formatted name.
func (e Entity) Name() string { return VCardName(e.VCard) }

// VCardName extracts and cleans fn, returning "" if absent.
func VCardName(vcard json.RawMessage) string {
	var card []json.RawMessage
	if json.Unmarshal(vcard, &card) != nil || len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(card[1], &props) != nil {
		return ""
	}
	for _, p := range props {
		var key, val string
		if len(p) >= 4 && json.Unmarshal(p[0], &key) == nil && key == "fn" && json.Unmarshal(p[3], &val) == nil {
			return strings.TrimSpace(sanitize.Text(val))
		}
	}
	return ""
}
