package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/knowledge/weburl"
	"github.com/rafaelh/nyx/internal/scope"
)

// DefaultUserAgent is the User-Agent of a build with no version.
const DefaultUserAgent = "nyx/devel"

const (
	// MaxTargetBody is the cap on Response.Body; Response.Truncated says whether it cut the body.
	MaxTargetBody = 1 << 20
	// MaxScriptBody allows larger script bundles than ordinary target responses, including
	// script redirects.
	MaxScriptBody = 4 << 20
)

// Reasons carried by NoService.
const (
	NoServiceRefused   = "refused"
	NoServiceTimeout   = "timeout"
	NoServiceTLSFailed = "tls-failed"
	NoServiceOther     = "other"
)

var errHTTPTimeout = errors.New("no complete response within the HTTP timeout")

// HTTPResult is the outcome of a target request: a Response, NoService or Refused.
type HTTPResult interface{ httpResult() }

// Response is an HTTP response. Redirects are never followed automatically.
type Response struct {
	Status   int
	Header   map[string][]string
	Body     []byte // capped at MaxTargetBody (MaxScriptBody for a Script request); empty for HEAD
	Location string
	// Truncated is set when the body cap cut the body.
	Truncated bool
	PeerCerts []*x509.Certificate
	// TLSVersion and TLSCipher record negotiated values; plain HTTP leaves both empty.
	TLSVersion, TLSCipher string

	tlsAt  time.Time // when a TLS response arrived; zero for plain HTTP
	origin *origin
}

// NoService means nothing answered HTTP at that address and port.
type NoService struct{ Reason string }

func (Response) httpResult()  {}
func (NoService) httpResult() {}
func (Refused) httpResult()   {}

// origin preserves the response's request URI so relative body/Location references resolve from
// the actual page URL.
type origin struct {
	scheme, host string
	port         int
	uri          string
	maxBody      int // the body cap the request was made with; a redirect keeps it
}

func (o *origin) base() *url.URL {
	u := &url.URL{Scheme: o.scheme, Host: weburl.HostPort(o.scheme, o.host, strconv.Itoa(o.port)), Path: "/"}
	if ru, err := url.ParseRequestURI(o.uri); err == nil {
		u.Path, u.RawPath, u.RawQuery = ru.Path, ru.RawPath, ru.RawQuery
	}
	return u
}

// URL is the absolute URL of the request that produced the response: the
// default port is omitted and an IPv6 literal is bracketed.
func (r Response) URL() string {
	if r.origin == nil {
		return ""
	}
	return r.origin.base().String()
}

// HeaderValue is the first value of the named header, matched case-insensitively,
// or "" if there is none.
func (r Response) HeaderValue(name string) string { return http.Header(r.Header).Get(name) }

// ContentType is the media type of the response, lower case and without
// parameters ("text/html"), or "" if there is none.
func (r Response) ContentType() string {
	v := r.HeaderValue("Content-Type")
	if v == "" {
		return ""
	}
	if mt, _, err := mime.ParseMediaType(v); err == nil {
		return mt
	}
	return strings.ToLower(strings.TrimSpace(strings.SplitN(v, ";", 2)[0]))
}

// Service identifies a web service for SensitivePath requests.
type Service struct {
	Host, Scheme string
	Port         int
}

// ParseService splits a web_service key (scheme://host[:port], an http or https
// origin) into a Service, with the scheme's default port if none is given.
func ParseService(origin string) (Service, bool) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Service{}, false
	}
	port := weburl.DefaultPort(u.Scheme)
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return Service{}, false
		}
	}
	return Service{Host: strings.ToLower(u.Hostname()), Scheme: u.Scheme, Port: port}, true
}

// Request represents a permitted target request. Constructors restrict URL and path choices;
// Script additionally requires a URL recorded in policy.
type Request interface{ target() target }

type target struct {
	scheme, host string
	port         int
	sensitive    int // 1 + the index into the sensitive-path list; 0 for none
	requestURI   string
	pin          netip.Addr // if valid, the only address dialled
	origin       bool       // set by OriginCheck: pin need not be an address of host (see OriginCheck)
	script       string     // set by Script: the URL, which Policy.Scripts must list
	maxBody      int        // 0 means MaxTargetBody
}

// bodyCap is how much of the response body is read.
func (t target) bodyCap() int {
	if t.maxBody == 0 {
		return MaxTargetBody
	}
	return t.maxBody
}

type req struct{ t target }

func (r req) target() target { return r.t }

// Root requests "/" of a service.
func Root(host, scheme string, port int) Request {
	return req{target{scheme: scheme, host: host, port: port, requestURI: "/"}}
}

// RootAt pins a named service's root request to one permitted address. Redirects and discovered
// links are not pinned.
func RootAt(host, scheme string, port int, addr netip.Addr) Request {
	return req{target{scheme: scheme, host: host, port: port, requestURI: "/", pin: addr.Unmap()}}
}

// OriginCheck sends GET / to addr on 443 or 80, using host for SNI and Host. host must be in
// scope; addr must pass exclusions and port eligibility, but need not be a current DNS address
// for host. Redirects are not followed.
func OriginCheck(host, scheme string, addr netip.Addr) Request {
	return req{target{scheme: scheme, host: host, port: weburl.DefaultPort(scheme), requestURI: "/", pin: addr.Unmap(), origin: true}}
}

// SensitivePath requests entry index of the configured sensitive-path list.
func SensitivePath(svc Service, index int) Request {
	return req{target{scheme: svc.Scheme, host: svc.Host, port: svc.Port, sensitive: index + 1}}
}

// Script fetches a crawled script URL listed in Policy.Scripts, after normal host-policy
// checks. Responses are capped at MaxScriptBody.
func Script(rawURL string) Request {
	var t target
	if u, err := url.Parse(rawURL); err == nil {
		if ut, err := targetOf(u); err == nil {
			t = ut
		}
	} // otherwise the empty scheme is refused
	t.script, t.maxBody = rawURL, MaxScriptBody
	return req{t}
}

// targetOf is the target a parsed URL names. A URL with userinfo is refused.
func targetOf(u *url.URL) (target, error) {
	if u.User != nil {
		return target{}, errors.New("userinfo is not permitted")
	}
	port := weburl.DefaultPort(u.Scheme)
	if ps := u.Port(); ps != "" {
		port, _ = strconv.Atoi(ps)
	}
	return target{scheme: u.Scheme, host: u.Hostname(), port: port, requestURI: u.RequestURI()}, nil
}

func resolveFrom(resp Response, ref string) (target, error) {
	if resp.origin == nil {
		return target{}, errors.New("response was not produced by egress")
	}
	u, err := resp.origin.base().Parse(ref)
	if err != nil {
		return target{}, err
	}
	t, err := targetOf(u)
	t.maxBody = resp.origin.maxBody
	return t, err
}

// Link requests a link found in a fetched response; it must be on the same host.
func Link(resp Response, href string) (Request, error) {
	t, err := resolveFrom(resp, href)
	if err != nil {
		return nil, err
	}
	if dnsname.Normalise(t.host) != dnsname.Normalise(resp.origin.host) {
		return nil, errors.New("link is not on the same host as the page it was found on")
	}
	return req{t}, nil
}

// Redirect requests the Location of a redirect response. Policy decides whether
// the destination may be contacted.
func Redirect(resp Response) (Request, error) {
	if resp.Location == "" {
		return nil, errors.New("response has no Location")
	}
	t, err := resolveFrom(resp, resp.Location)
	if err != nil {
		return nil, err
	}
	return req{t}, nil
}

// TargetHTTP issues GET and HEAD requests to in-scope services. Credentials,
// cookies, caller-supplied headers and other methods do not exist in this API.
type TargetHTTP interface {
	Get(ctx context.Context, r Request) (HTTPResult, error)
	Head(ctx context.Context, r Request) (HTTPResult, error)
}

type targetHTTP struct{ e *Egress }

func (t *targetHTTP) Get(ctx context.Context, r Request) (HTTPResult, error) {
	return t.do(ctx, http.MethodGet, r)
}

func (t *targetHTTP) Head(ctx context.Context, r Request) (HTTPResult, error) {
	return t.do(ctx, http.MethodHead, r)
}

func (t *targetHTTP) do(ctx context.Context, method string, r Request) (HTTPResult, error) {
	tg := r.target()
	pl, refusal, refused := t.e.policy().planHTTP(tg)
	if refused {
		return refusal, nil
	}
	return t.e.fetch(ctx, method, tg, pl)
}

// httpPlan contains a policy-approved host, request URI and ordered dial addresses.
type httpPlan struct {
	host  string
	uri   string
	addrs []netip.Addr
}

// planHTTP checks target permission, recorded scripts, URL shape, host scope, port, path and
// dial addresses in order. Refusals include a reason.
func (p *Policy) planHTTP(tg target) (httpPlan, Refused, bool) {
	if r, ok := p.targetRefusal(); ok {
		return httpPlan{}, r, true
	}
	if tg.script != "" && !p.Scripts[tg.script] {
		return httpPlan{}, Refused{"script URL is not one the crawl recorded"}, true
	}
	host := dnsname.Normalise(tg.host)
	lit, isIP := input.IPLiteral(host)
	if r, refused := shapeRefusal(tg, isIP); refused {
		return httpPlan{}, r, true
	}
	if isIP {
		host = lit.String()
	}
	if r, refused := p.webScopeRefusal(host, lit, isIP); refused {
		return httpPlan{}, r, true
	}
	if !p.portAllowed(tg.port, true) {
		return httpPlan{}, Refused{"port " + strconv.Itoa(tg.port) + " not allowed"}, true
	}
	uri, r, refused := p.requestURI(tg)
	if refused {
		return httpPlan{}, r, true
	}
	addrs, r, refused := p.dialAddrs(tg, host, lit, isIP)
	if refused {
		return httpPlan{}, r, true
	}
	return httpPlan{host: host, uri: uri, addrs: addrs}, Refused{}, false
}

// shapeRefusal refuses a scheme other than http or https, a malformed host or port, and an
// origin check that names an address.
func shapeRefusal(tg target, isIP bool) (Refused, bool) {
	switch {
	case tg.scheme != "http" && tg.scheme != "https":
		return Refused{"scheme " + strconv.Quote(tg.scheme) + " is not http or https"}, true
	case tg.host == "" || tg.port < 1 || tg.port > 65535 || (!isIP && strings.ContainsAny(tg.host, "@/?#: \\[]%")):
		return Refused{"malformed host or port"}, true
	case tg.origin && isIP:
		return Refused{"an origin check names a hostname, not an address"}, true
	}
	return Refused{}, false
}

// webScopeRefusal enforces host/address scope and reports excluded addresses. host is already
// normalised.
func (p *Policy) webScopeRefusal(host string, lit netip.Addr, isIP bool) (Refused, bool) {
	if !isIP {
		switch c := p.Scope.ClassifyHost(host); c.Class {
		case scope.Excluded:
			return Refused{"host is excluded: " + c.Reason}, true
		case scope.Candidate:
			return Refused{"host is not in scope"}, true
		case scope.InScope:
		}
		return Refused{}, false
	}
	// IP-literal web targets require in-scope netblock membership after exclusions.
	// Hostname services are probed by name.
	if !p.Scope.InScopeIP(lit) {
		return Refused{"address is not in scope"}, true
	}
	if ex, why := p.Scope.ExcludedFor(lit, p.isShared(lit)); ex {
		p.reportExcluded(lit.String(), why)
		return Refused{"address is excluded: " + why}, true
	}
	return Refused{}, false
}

// requestURI is the URI to request: the target's own, or the configured sensitive path it
// names. It must start with "/".
func (p *Policy) requestURI(tg target) (string, Refused, bool) {
	uri := tg.requestURI
	if tg.sensitive != 0 {
		i := tg.sensitive - 1
		if i < 0 || i >= len(p.SensitivePaths) {
			return "", Refused{"sensitive path index out of range"}, true
		}
		uri = p.SensitivePaths[i]
	}
	if !strings.HasPrefix(uri, "/") {
		return "", Refused{"request path " + strconv.Quote(uri) + " does not start with /"}, true
	}
	return uri, Refused{}, false
}

// dialAddrs selects the literal, candidate-origin or vetted DNS addresses, applying any address
// pin.
func (p *Policy) dialAddrs(tg target, host string, lit netip.Addr, isIP bool) ([]netip.Addr, Refused, bool) {
	addrs := []netip.Addr{lit}
	switch {
	case tg.origin:
		// Candidate origins need not match current DNS. Their addresses still need port
		// eligibility: an in-scope netblock or known dedicated hosting, after
		// exclusions.
		if !tg.pin.IsValid() {
			return nil, Refused{"no address"}, true
		}
		if r, refused := p.portIneligible(tg.pin); refused {
			return nil, r, true
		}
		addrs = []netip.Addr{tg.pin}
	case !isIP:
		addrs = p.vetted(host)
	}
	if len(addrs) == 0 {
		return nil, Refused{"no permitted address for " + host}, true
	}
	if tg.pin.IsValid() {
		if !slices.Contains(addrs, tg.pin) {
			return nil, Refused{"address " + tg.pin.String() + " is not a permitted address of " + host}, true
		}
		addrs = []netip.Addr{tg.pin}
	}
	return addrs, Refused{}, false
}

// fetch sends a planned request, without following redirects, and reads the response body up to
// the target's cap.
func (e *Egress) fetch(ctx context.Context, method string, tg target, pl httpPlan) (HTTPResult, error) {
	// HTTPTimeout runs from when the rate limiter lets the first dial through,
	// so waiting for a token never makes a service look unresponsive.
	parent := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	deadline := sync.OnceValue(func() *time.Timer {
		return time.AfterFunc(e.opts.HTTPTimeout, func() { cancel(errHTTPTimeout) })
	})
	defer func() { deadline().Stop() }()
	reqURL := (&url.URL{Scheme: tg.scheme, Host: weburl.HostPort(tg.scheme, pl.host, strconv.Itoa(tg.port))}).String() + pl.uri
	hreq, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return Refused{"bad request: " + err.Error()}, nil
	}
	hreq.Header.Set("User-Agent", e.opts.UserAgent)

	tr := &http.Transport{
		Proxy:              nil,
		DisableKeepAlives:  true,
		DisableCompression: true,
		TLSClientConfig:    targetTLSConfig(pl.host),
		DialContext:        e.dialFirst(pl.addrs, tg.port, deadline),
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(hreq)
	if err != nil {
		return requestFailure(parent, ctx, err)
	}
	defer resp.Body.Close()
	body, truncated, err := readCapped(resp.Body, tg.bodyCap())
	if err != nil { // a body that fails mid-read is not a result; retry it next run
		return nil, bodyFailure(parent, ctx, pl.host, err)
	}
	if method == http.MethodHead {
		body, truncated = nil, false
	}
	out := Response{
		Status: resp.StatusCode, Header: resp.Header, Body: body, Truncated: truncated,
		Location: resp.Header.Get("Location"),
		origin:   &origin{scheme: tg.scheme, host: pl.host, port: tg.port, uri: pl.uri, maxBody: tg.maxBody},
	}
	if resp.TLS != nil {
		out.PeerCerts, out.tlsAt = resp.TLS.PeerCertificates, e.opts.Now()
		out.TLSVersion, out.TLSCipher = tls.VersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite)
	}
	return out, nil
}

// dialFirst tries addresses in order after each host's rate limiter and returns the first
// connection. The HTTP deadline starts with the first dial.
func (e *Egress) dialFirst(addrs []netip.Addr, port int, deadline func() *time.Timer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var last error
		for _, a := range addrs {
			if err := e.hostLimiter(a).Wait(ctx); err != nil {
				return nil, err
			}
			deadline()
			d := net.Dialer{Timeout: e.opts.ConnectTimeout}
			c, err := d.DialContext(ctx, "tcp", e.dialAddr(a, port))
			if err == nil {
				return c, nil
			}
			last = localRoute(err, a, udpRoute)
		}
		return nil, last
	}
}

// requestFailure preserves cancellation/local errors; other failures mean no HTTP service
// answered.
func requestFailure(parent, ctx context.Context, err error) (HTTPResult, error) {
	switch perr := parent.Err(); {
	case perr != nil && !errors.Is(perr, context.DeadlineExceeded):
		return nil, perr
	case errors.Is(context.Cause(ctx), errHTTPTimeout):
		return NoService{NoServiceTimeout}, nil
	case localFailure(err):
		return nil, err
	}
	return NoService{classify(err)}, nil
}

// bodyFailure preserves run cancellation; otherwise it reports a body-read failure for host,
// using errHTTPTimeout when the request deadline expired.
func bodyFailure(parent, ctx context.Context, host string, err error) error {
	if perr := parent.Err(); perr != nil {
		return perr
	}
	if errors.Is(context.Cause(ctx), errHTTPTimeout) {
		err = errHTTPTimeout
	}
	return fmt.Errorf("reading response body from %s: %w", host, err)
}

// readCapped reads r up to n bytes. It reads one byte past the cap, to tell a
// cut body from one that fits.
func readCapped(r io.Reader, n int) (body []byte, truncated bool, err error) {
	body, err = io.ReadAll(io.LimitReader(r, int64(n)+1))
	if len(body) > n {
		return body[:n], true, err
	}
	return body, false, err
}

// vetted removes excluded CIDRs and addresses of name-excluded hosts. Known shared
// infrastructure is exempt only from name-based exclusions.
func (p *Policy) vetted(host string) []netip.Addr {
	var out []netip.Addr
	for _, a := range p.Scope.Addrs(host) {
		if ok, why := p.Scope.ExcludedFor(a, p.isShared(a)); ok {
			p.reportExcluded(a.String(), why)
			continue
		}
		out = append(out, a)
	}
	return out
}

func classify(err error) string {
	var ne net.Error
	var rh tls.RecordHeaderError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return NoServiceRefused
	case errors.As(err, &rh), strings.Contains(err.Error(), "tls:"), strings.Contains(err.Error(), "x509:"),
		strings.Contains(err.Error(), "server gave HTTP response to HTTPS client"):
		return NoServiceTLSFailed
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return NoServiceTimeout
	}
	return NoServiceOther
}
