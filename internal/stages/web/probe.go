package web

import (
	"context"
	"fmt"
	"iter"
	"net/netip"
	"strings"

	"github.com/rafaelh/nyx/internal/cloudstorage"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// maxHops is how many redirects a probe, the crawl or jsparse follows.
const maxHops = 10

// Probe is the httpprobe stage: it finds the HTTP and HTTPS services of every
// probe hostname and of every in-scope IP with an open port, and records each
// with what an ordinary browser would see.
type Probe struct{}

// NewProbe returns the httpprobe stage.
func NewProbe() *Probe { return &Probe{} }

func (*Probe) Name() string                      { return "httpprobe" }
func (*Probe) Contact() run.Contact              { return run.Target }
func (*Probe) Sources() []string                 { return nil }
func (*Probe) Configured(run.Env) (bool, string) { return true, "" }

// probeInput is the Check.Input of httpprobe.
type probeInput struct {
	host   string // hostname, or an IP literal
	port   int
	scheme string // "" tries https, then http
	detect bool   // a port-detection check, not a hostname check
	addr   netip.AddrPort
}

// Checks yields h:80 and h:443 for every probe hostname, one detection
// check per open port with no banner whose representative has not already
// been given one on that port, and h:port for the other names on each
// address that answered HTTP. A key may repeat; the runner keeps the first.
func (*Probe) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		if _, err := fingerprints(); err != nil {
			v.Warn("httpprobe: technology detection is off: %v", err)
		}
		emit := func(key string, in probeInput) bool {
			return yield(run.Check{Key: key, Input: in}, nil)
		}
		for _, h := range v.ProbeHostnames() {
			if !emit(fmt.Sprintf("%s:80", h), probeInput{host: h, port: 80, scheme: "http"}) ||
				!emit(fmt.Sprintf("%s:443", h), probeInput{host: h, port: 443, scheme: "https"}) {
				return
			}
		}
		if !detectionChecks(v, emit) {
			return
		}
		sharedAddressChecks(v, emit)
	}
}

// probeEmit yields one check, reporting whether to go on.
type probeEmit func(key string, in probeInput) bool

// detectionChecks yields one detection check per open port with no banner
// whose representative has not already been given one on that port. It
// reports whether to go on.
func detectionChecks(v run.View, emit probeEmit) bool {
	sc := v.Scope()
	detecting := map[string]bool{} // "rep:port" of the detection checks yielded
	for _, op := range v.OpenPorts() {
		if op.Banner != "" { // HTTP servers never speak first
			continue
		}
		addr, port := op.Addr.Addr(), int(op.Addr.Port())
		rep, isName := "", false
		if hosts := v.HostsFor(addr); len(hosts) > 0 {
			rep, isName = hosts[0], true
		} else if sc.WebHostInScope(addr.String()) {
			rep = addr.String()
		}
		if rep == "" || (isName && (port == 80 || port == 443)) {
			continue
		}
		// A name on several addresses is tested on one of them.
		rp := fmt.Sprintf("%s:%d", rep, port)
		if detecting[rp] {
			continue
		}
		detecting[rp] = true
		in := probeInput{host: rep, port: port, detect: true, addr: op.Addr}
		switch port {
		case 80:
			in.scheme = "http"
		case 443:
			in.scheme = "https"
		}
		if !emit("port|"+op.Addr.String(), in) {
			return false
		}
	}
	return true
}

// sharedAddressChecks yields h:port for the other names on each address that
// answered HTTP, unless a representative already answered on that port, on
// whichever address.
func sharedAddressChecks(v run.View, emit probeEmit) {
	reps := map[string]bool{}
	ports := v.Records(kinds.HTTPPort)
	for _, rec := range ports {
		if ap, ok := kinds.ParsePortKey(rec.Key); ok {
			reps[fmt.Sprintf("%s:%d", kinds.HTTPPort.Attrs(rec).Host, ap.Port())] = true
		}
	}
	for _, rec := range ports {
		ap, ok := kinds.ParsePortKey(rec.Key)
		if !ok {
			continue
		}
		for _, h := range v.HostsFor(ap.Addr()) {
			if !reps[fmt.Sprintf("%s:%d", h, ap.Port())] && !emit(fmt.Sprintf("%s:%d", h, ap.Port()), probeInput{host: h, port: int(ap.Port()), scheme: kinds.HTTPPort.Attrs(rec).Scheme}) {
				return
			}
		}
	}
}

// Run probes one service. A live answer (any status) is recorded; NoService and
// Refused complete the check with nothing. On an undecided port https is
// tried first, then http unless the connection was refused.
func (p *Probe) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(probeInput)
	schemes := []string{in.scheme}
	if in.scheme == "" {
		schemes = []string{"https", "http"}
	}
	for i, scheme := range schemes {
		req := egress.Root(in.host, scheme, in.port)
		if in.detect { // the http_port record is about this address, not the name's others
			req = egress.RootAt(in.host, scheme, in.port, in.addr.Addr())
		}
		res, err := e.HTTP.Get(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Key, err)
		}
		switch r := res.(type) {
		case egress.Response:
			obs, err := p.service(ctx, in, scheme, r, e)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.Key, err)
			}
			if in.detect {
				obs = append(obs, kinds.HTTPPort.Obs(in.addr.String(), kinds.HTTPPortAttrs{Scheme: scheme, Host: in.host}))
			}
			return obs, nil
		case egress.NoService:
			if i+1 < len(schemes) && r.Reason != egress.NoServiceRefused {
				continue
			}
		}
		return nil, nil
	}
	return nil, nil
}

// obsSet collects observations without duplicates.
type obsSet struct {
	seen map[string]bool
	list []run.Observation
}

func newObsSet() *obsSet { return &obsSet{seen: map[string]bool{}} }

// add adds o unless the set has an observation of its record already, and
// returns o's index in the list, or -1 if it was not added.
func (s *obsSet) add(o run.Observation) int {
	if k := o.Kind + "\x00" + o.Key; !s.seen[k] {
		s.seen[k] = true
		s.list = append(s.list, o)
		return len(s.list) - 1
	}
	return -1
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// redirectTarget is the normalised absolute URL a redirect response points to.
func redirectTarget(r egress.Response) (string, bool) { return resolve(r.URL(), r.Location) }

// otherHost is host as a hostname observation, if it is a domain other than
// self. The probed host itself would turn a permutation-only name into a seed,
// and an IP literal would land in candidates.csv.
func otherHost(host, self string) (string, bool) {
	if host == strings.ToLower(self) {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	d, err := input.ParseDomain(host)
	return d, err == nil
}

// service builds the web_service record from the first response and the page
// the redirect chain ends on, following in-scope redirects.
func (p *Probe) service(ctx context.Context, in probeInput, scheme string, first egress.Response, e egress.Clients) ([]run.Observation, error) {
	obs := newObsSet()
	chain, err := followRedirects(ctx, in, first, e, obs)
	if err != nil {
		return nil, err
	}
	last := chain[len(chain)-1].resp

	attrs := kinds.WebServiceAttrs{
		URL: Origin(scheme, in.host, in.port), Host: in.host, Port: in.port, Scheme: scheme,
		Status: first.Status, Server: last.HeaderValue("Server"),
		Technologies: technologies(last.Header, last.Body),
		Redirect:     first.Location,
	}
	if u, ok := NormaliseURL(last.URL()); ok {
		attrs.FinalURL = u
	}
	if pg, ok := chain[len(chain)-1].page(); ok {
		attrs.Title = pg.title()
	}
	attrs.BodyLen = len(first.Body)
	attrs.TLSVersion, attrs.TLSCipher = first.TLSVersion, first.TLSCipher
	if len(first.PeerCerts) > 0 {
		certAttrs(&attrs, first, in.host, obs)
	}
	ids := newIdentifierSet(attrs.URL, in.host, obs)
	ids.chain(chain)
	hash, err := fetchFavicon(ctx, chain, e)
	if err != nil {
		return nil, err
	}
	ids.add(kinds.IdentifierFavicon, hash)
	return append([]run.Observation{kinds.WebService.Obs(attrs.URL, attrs), kinds.WebPosture.Obs(attrs.URL, posture(in.host, chain))}, obs.list...), nil
}

// followRedirects follows the in-scope redirects from first, at most maxHops
// of them, recording each hop's URL, any other hostname it names and any
// storage reference it is. It returns the chain of responses, first included.
func followRedirects(ctx context.Context, in probeInput, first egress.Response, e egress.Clients, obs *obsSet) ([]*hop, error) {
	last := first
	chain := []*hop{newHop(first)}
	visited := map[string]bool{}
	if u, ok := NormaliseURL(first.URL()); ok {
		visited[u] = true
	}
	for n := 0; n < maxHops && isRedirect(last.Status) && last.Location != ""; n++ {
		target, ok := redirectTarget(last)
		if !ok {
			break
		}
		hopURL := kinds.URLAttrs{URL: target, Host: HostOfURL(target)}
		hopIdx := recordHop(obs, in.host, last, hopURL)
		if visited[target] {
			break
		}
		visited[target] = true
		req, err := egress.Redirect(last)
		if err != nil {
			break
		}
		res, err := e.HTTP.Get(ctx, req)
		if err != nil {
			return nil, err
		}
		next, ok := res.(egress.Response)
		if !ok { // out of scope, excluded, unresolved or not answering: the chain stops here
			break
		}
		if hopIdx >= 0 { // a fetched url carries its status
			hopURL.Status = next.Status
			obs.list[hopIdx] = kinds.URL.Obs(target, hopURL)
		}
		last = next
		chain = append(chain, newHop(next))
	}
	return chain, nil //nolint:nilerr // a redirect that cannot be followed ends the chain, which is a result, not a failure
}

// recordHop records the URL a redirect from last points to, the hostname it
// names if that is another domain, and the storage reference it is, if any. It
// returns the URL observation's index in obs, or -1 if it was there already.
func recordHop(obs *obsSet, self string, last egress.Response, hopURL kinds.URLAttrs) int {
	target := hopURL.URL
	hopIdx := obs.add(kinds.URL.Obs(target, hopURL))
	if d, ok := otherHost(hopURL.Host, self); ok {
		obs.add(kinds.Hostname.Obs(d, kinds.HostnameAttrs{}))
	}
	// A redirect to a storage URL is a reference, and a browser follows it.
	if ref, ok := cloudstorage.ParseRef(target); ok {
		if page, ok := NormaliseURL(last.URL()); ok {
			obs.add(storageObservation(storageRef{ref: ref, url: target, page: page, via: "asset"}))
		}
	}
	return hopIdx
}

// certAttrs fills in the TLS certificate attributes from the first response's
// leaf certificate, and records each other name it covers as a hostname.
func certAttrs(attrs *kinds.WebServiceAttrs, first egress.Response, host string, obs *obsSet) {
	leaf := first.PeerCerts[0]
	sans := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	isSelfSigned := first.SelfSigned()
	attrs.TLSSubject = leaf.Subject.String()
	attrs.TLSSANs = strings.Join(sans, ";")
	attrs.TLSIssuer = leaf.Issuer.String()
	attrs.TLSExpiry = leaf.NotAfter.UTC().Format("2006-01-02")
	attrs.TLSTrust = first.CertTrust()
	attrs.TLSSelfSigned = &isSelfSigned
	for _, name := range leaf.DNSNames {
		// A wildcard contributes its base name; malformed names, IP literals
		// and public suffixes are skipped.
		if d := httpsrc.CleanName(name); d != "" && d != strings.ToLower(host) {
			obs.add(kinds.Hostname.Obs(d, kinds.HostnameAttrs{}))
		}
	}
}
