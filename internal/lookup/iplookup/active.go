package iplookup

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/webpage"
)

// commonPorts are the ports --active connects to on every contacted address, whatever InternetDB
// reports.
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 853, 993, 995,
	1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 9443, 11211, 27017,
}

// tlsPorts are the ports a TLS handshake is made on once they are open.
var tlsPorts = []int{443, 465, 636, 853, 993, 995, 8443, 9443}

// webPorts are the ports GET / is sent to once they are open.
var webPorts = []int{80, 443, 8000, 8080, 8443, 8888, 9443}

// maxExtraPorts is the most ports beyond the common list that InternetDB adds.
const maxExtraPorts = 64

// probePorts tries common ports before sorted, unique InternetDB additions, capped at
// maxExtraPorts.
func probePorts(extra []int) []int {
	out := slices.Clone(commonPorts)
	var more []int
	for _, p := range extra {
		if p >= 1 && p <= 65535 && !slices.Contains(out, p) && !slices.Contains(more, p) {
			more = append(more, p)
		}
	}
	slices.Sort(more)
	if len(more) > maxExtraPorts {
		more = more[:maxExtraPorts]
	}
	return append(out, more...)
}

func tlsPort(p int) bool { return slices.Contains(tlsPorts, p) }

func webPort(p int) bool { return slices.Contains(webPorts, p) }

// contactInput supplies discovery sources and ownership for active-contact decisions.
type contactInput struct {
	Addr  netip.Addr
	Kind  addrkind.Kind
	Found Found
	// OwnerFailed preserves failed public ownership lookup; nil means it answered.
	OwnerFailed *Failure
	// Provider supplies public-address hosting classification.
	Provider provider.Result
}

// notContacted is why --active sends the address nothing, or "" when it contacts it.
func notContacted(in contactInput) string {
	if slices.Contains([]addrkind.Kind{"unspecified", "this-network", "multicast", "broadcast"}, in.Kind) {
		return string(in.Kind) + " address"
	}
	if in.Kind == "link-local" && in.Addr.Is6() {
		return "IPv6 link-local address (needs a zone to be dialled)"
	}
	if in.Kind != addrkind.Public {
		if in.Found.OnlyPublicDNS() {
			return "non-public address from public DNS"
		}
		return ""
	}
	if in.OwnerFailed != nil {
		return fmt.Sprintf("owner unknown: cymru %s", in.OwnerFailed.Code)
	}
	if in.Provider.SharedInfrastructure() {
		if in.Provider.Class == "" {
			return fmt.Sprintf("shared provider infrastructure (%s)", in.Provider.Provider)
		}
		return fmt.Sprintf("shared provider infrastructure (%s, %s)", in.Provider.Provider, in.Provider.Class)
	}
	return ""
}

// probeJob is one address to probe.
type probeJob struct {
	Addr      netip.Addr
	Hostnames []string
	Ports     []int
	// TLS and Web say whether to make the handshakes and the GET / requests.
	TLS, Web bool
}

// probeOutcome holds probe results and any first local failure.
type probeOutcome struct {
	Ports   []Port
	TLS     []TLSEntry
	Web     []WebEntry
	Failure *Failure
}

// probeRun holds the state of one probe.
type probeRun struct {
	p   egress.Probe
	j   probeJob
	mu  sync.Mutex
	bad *Failure
}

// fail retains the first local/policy failure. Context termination means the probe was
// interrupted, not that the source failed.
func (r *probeRun) fail(ctx context.Context, err error) {
	if ctx.Err() != nil || timedOut(ctx, err) {
		return
	}
	r.set(Failure{Source: SourceProbe, Code: clierr.NetworkError, Message: err.Error(), Transient: true})
}

func (r *probeRun) set(f Failure) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bad == nil {
		r.bad = &f
	}
}

// runProbe checks ports, then performs TLS/HTTP probes on open ports. Remote responses are
// results; only host-side failures produce Failure values.
func runProbe(ctx context.Context, p egress.Probe, j probeJob) probeOutcome {
	r := &probeRun{p: p, j: j}
	ports := slices.Clone(j.Ports)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	out := probeOutcome{Ports: r.scan(ctx, ports)}
	open := map[int]bool{}
	for _, e := range out.Ports {
		open[e.Port] = e.State == PortOpen
	}
	var wg sync.WaitGroup
	if j.TLS {
		wg.Go(func() { out.TLS = r.handshakes(ctx, ports, open) })
	}
	if j.Web {
		wg.Go(func() { out.Web = r.requests(ctx, ports, open) })
	}
	wg.Wait()
	out.Failure = r.bad
	return out
}

// scan connects to every port at once, behind the host limiter.
func (r *probeRun) scan(ctx context.Context, ports []int) []Port {
	out := make([]Port, len(ports))
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Go(func() {
			out[i] = Port{Port: port, State: PortNotProbed}
			res, err := r.p.TCP.Connect(ctx, r.j.Addr, port)
			if err != nil {
				r.fail(ctx, err)
				return
			}
			switch v := res.(type) {
			case egress.Open:
				out[i].State = PortOpen
				if b := BannerText(v.Banner); b != "" {
					out[i].Banner = &b
				}
			case egress.Closed:
				out[i].State = PortClosed
			case egress.Filtered:
				out[i].State = PortNoAnswer
			case egress.Refused:
				r.set(Failure{Source: SourceProbe, Code: clierr.NetworkError, Message: "probe refused: " + v.Reason})
			}
		})
	}
	wg.Wait()
	return out
}

// hosts are the names a handshake or request is made for: the input hostnames, or one "" for none.
func (r *probeRun) hosts() []string {
	if len(r.j.Hostnames) == 0 {
		return []string{""}
	}
	return r.j.Hostnames
}

// handshakes makes one handshake per open TLS port and server name.
func (r *probeRun) handshakes(ctx context.Context, ports []int, open map[int]bool) []TLSEntry {
	var out []TLSEntry
	for _, port := range ports {
		if !open[port] || !tlsPort(port) {
			continue
		}
		for _, name := range r.hosts() {
			e := TLSEntry{Port: port, Outcome: OutcomeNotProbed, Names: []string{}}
			if name != "" {
				e.ServerName = &name
			}
			out = append(out, e)
		}
	}
	var wg sync.WaitGroup
	for i := range out {
		wg.Go(func() { r.handshake(ctx, &out[i]) })
	}
	wg.Wait()
	return out
}

func (r *probeRun) handshake(ctx context.Context, e *TLSEntry) {
	if ctx.Err() != nil {
		return
	}
	name := ""
	if e.ServerName != nil {
		name = *e.ServerName
	}
	res, err := r.p.TLS.Handshake(ctx, r.j.Addr, e.Port, name)
	if err != nil {
		r.fail(ctx, err)
		return
	}
	switch v := res.(type) {
	case egress.TLSCert:
		e.Outcome = OutcomeOK
		e.Names = append([]string{}, v.Names...)
		if v.Issuer != "" {
			e.Issuer = &v.Issuer
		}
		if !v.NotAfter.IsZero() {
			x := Expiry(v.NotAfter)
			e.Expiry = &x
		}
	case egress.NoService:
		e.Outcome = noServiceOutcome(v.Reason)
	case egress.Refused:
		r.set(Failure{Source: SourceProbe, Code: clierr.NetworkError, Message: "probe refused: " + v.Reason})
	}
}

// noServiceOutcome translates unanswered TLS/HTTP probes into result entries.
func noServiceOutcome(reason string) string {
	switch reason {
	case egress.NoServiceTimeout:
		return OutcomeNoAnswer
	case egress.NoServiceRefused:
		return OutcomeRefused
	case egress.NoServiceTLSFailed:
		return OutcomeNotTLS
	}
	return OutcomeReset
}

// requests sends GET / once per open web port and host.
func (r *probeRun) requests(ctx context.Context, ports []int, open map[int]bool) []WebEntry {
	var out []WebEntry
	for _, port := range ports {
		if !open[port] || !webPort(port) {
			continue
		}
		scheme := "http"
		if tlsPort(port) {
			scheme = "https"
		}
		for _, name := range r.hosts() {
			host := name
			if host == "" {
				host = r.j.Addr.String()
			}
			out = append(out, WebEntry{Port: port, Scheme: scheme, Host: host, Outcome: OutcomeNotProbed})
		}
	}
	var wg sync.WaitGroup
	for i := range out {
		wg.Go(func() {
			e := &out[i]
			if ctx.Err() != nil {
				return
			}
			req := egress.Root(e.Host, e.Scheme, e.Port)
			if len(r.j.Hostnames) > 0 {
				req = egress.RootAt(e.Host, e.Scheme, e.Port, r.j.Addr)
			}
			res, err := r.p.HTTP.Get(ctx, req)
			if err != nil {
				r.fail(ctx, err)
				return
			}
			switch v := res.(type) {
			case egress.Response:
				fillWeb(e, v)
			case egress.NoService:
				e.Outcome = noServiceOutcome(v.Reason)
			case egress.Refused:
				r.set(Failure{Source: SourceProbe, Code: clierr.NetworkError, Message: "probe refused: " + v.Reason})
			}
		})
	}
	wg.Wait()
	return out
}

func fillWeb(e *WebEntry, v egress.Response) {
	e.Outcome = OutcomeOK
	status := v.Status
	e.Status = &status
	if s := v.HeaderValue("Server"); s != "" {
		e.Server = &s
	}
	if t := webpage.Title(v.Body); t != "" {
		e.Title = &t
	}
	loc := v.Location
	if loc == "" {
		loc = v.HeaderValue("Location")
	}
	if loc != "" {
		e.Location = &loc
	}
}
