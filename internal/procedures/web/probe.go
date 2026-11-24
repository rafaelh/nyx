// Package web implements service probing, crawling and script/endpoint discovery. All network
// requests go through egress.
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
	"github.com/rafaelh/nyx/internal/weburl"
)

// maxHops is how many redirects a probe, the crawl or jsparse follows.
const maxHops = 10

// Probe finds HTTP/HTTPS services on probe hostnames and in-scope addresses with open ports,
// recording their responses.
type Probe struct{}

// NewProbe returns the httpprobe procedure.
func NewProbe() *Probe { return &Probe{} }

func (*Probe) Name() string { return "httpprobe" }

// CandidateSources: the probe is a family of its own.
func (*Probe) CandidateSources() map[string]string {
	return map[string]string{"httpprobe": "httpprobe"}
}
func (*Probe) Contact() run.Contact              { return run.Target }
func (*Probe) Sources() []string                 { return nil }
func (*Probe) Configured(run.Env) (bool, string) { return true, "" }

// probeInput is the Job.Input of httpprobe.
type probeInput struct {
	host   string // hostname, or an IP literal
	port   int
	scheme string // "" tries https, then http
	detect bool   // a port-detection job, not a hostname job
	addr   netip.AddrPort
}

// Jobs starts with hostname ports 80/443, detects protocols on other bannerless open ports,
// then adds other hostnames sharing HTTP addresses. Duplicate keys are harmless because the
// runner deduplicates them.
func (*Probe) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		if _, err := fingerprints(); err != nil {
			v.Warn("httpprobe: technology detection is off: %v", err)
		}
		emit := func(key string, in probeInput) bool {
			return yield(run.Job{Key: key, Input: in}, nil)
		}
		for _, h := range v.ProbeHostnames() {
			if !emit(fmt.Sprintf("%s:80", h), probeInput{host: h, port: 80, scheme: "http"}) ||
				!emit(fmt.Sprintf("%s:443", h), probeInput{host: h, port: 443, scheme: "https"}) {
				return
			}
		}
		if !detectionJobs(v, emit) {
			return
		}
		sharedAddressJobs(v, emit)
	}
}

// probeEmit yields one job, reporting whether to go on.
type probeEmit func(key string, in probeInput) bool

// detectionJobs yields unrepresented bannerless open ports for protocol detection, returning
// whether enumeration should continue.
func detectionJobs(v run.View, emit probeEmit) bool {
	sc := v.Scope()
	detecting := map[string]bool{} // "rep:port" of the detection jobs yielded
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

// sharedAddressJobs adds other names on HTTP-speaking addresses unless a representative
// already answered on that port.
func sharedAddressJobs(v run.View, emit probeEmit) {
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

// Run records any live HTTP response. NoService/Refused complete empty. Undecided protocols try
// HTTPS then HTTP unless the connection itself was refused.
func (p *Probe) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
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

// add deduplicates observations by record identity, returning the appended index or -1.
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

// otherHost records only a different domain name. Recording self would incorrectly promote
// permutation-only names to generator seeds; IP literals are not hostname candidates.
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

// service combines first-response metadata with the final page after in-scope redirects.
func (p *Probe) service(ctx context.Context, in probeInput, scheme string, first egress.Response, e egress.Clients) ([]run.Observation, error) {
	obs := newObsSet()
	chain, err := followRedirects(ctx, in, first, e, obs)
	if err != nil {
		return nil, err
	}
	last := chain[len(chain)-1].resp

	attrs := kinds.WebServiceAttrs{
		URL: weburl.Origin(scheme, in.host, in.port), Host: in.host, Port: in.port, Scheme: scheme,
		Status: first.Status, Server: last.HeaderValue("Server"),
		Technologies: technologies(last.Header, last.Body),
		Redirect:     first.Location,
	}
	if u, ok := weburl.NormaliseURL(last.URL()); ok {
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

// followRedirects follows up to maxHops in-scope redirects, recording URLs, other hosts and
// storage references. The returned response chain includes first.
func followRedirects(ctx context.Context, in probeInput, first egress.Response, e egress.Clients, obs *obsSet) ([]*hop, error) {
	last := first
	chain := []*hop{newHop(first)}
	visited := map[string]bool{}
	if u, ok := weburl.NormaliseURL(first.URL()); ok {
		visited[u] = true
	}
	for n := 0; n < maxHops && isRedirect(last.Status) && last.Location != ""; n++ {
		target, ok := redirectTarget(last)
		if !ok {
			break
		}
		hopURL := kinds.URLAttrs{URL: target, Host: weburl.HostOfURL(target)}
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

// recordHop records redirect URL, any different domain and storage reference. It returns the
// new URL observation's index, or -1 for a duplicate.
func recordHop(obs *obsSet, self string, last egress.Response, hopURL kinds.URLAttrs) int {
	target := hopURL.URL
	hopIdx := obs.add(kinds.URL.Obs(target, hopURL))
	if d, ok := otherHost(hopURL.Host, self); ok {
		obs.add(kinds.Hostname.Obs(d, kinds.HostnameAttrs{}))
	}
	// A redirect to a storage URL is a reference, and a browser follows it.
	if ref, ok := cloudstorage.ParseRef(target); ok {
		if page, ok := weburl.NormaliseURL(last.URL()); ok {
			obs.add(storageObservation(storageRef{ref: ref, url: target, page: page, via: "asset"}))
		}
	}
	return hopIdx
}

// certAttrs records certificate metadata and other valid DNS names as hostname observations.
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
		// Wildcard SANs contribute base names; invalid names, IPs and public suffixes
		// are ignored.
		if d := input.CleanName(name); d != "" && d != strings.ToLower(host) {
			obs.add(kinds.Hostname.Obs(d, kinds.HostnameAttrs{}))
		}
	}
}
