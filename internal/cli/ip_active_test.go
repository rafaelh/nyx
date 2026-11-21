package cli_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	mdns "github.com/miekg/dns"
)

// nyx ip --active: which addresses are contacted, the TCP scan, the TLS handshakes and the GETs, and
// the keys they add. Every address nyx may connect to is mapped (Options.DialMap) to a loopback
// server of ip_world_test.go or of this file, so a test sees exactly which connections were made and
// what was sent on them.

// ---- fixtures ----

// activeWorld is a world whose probes are quick: a silent open port is told apart from a banner after
// 300 ms, and a port that does not answer after 500 ms.
func activeWorld(t *testing.T) *ipWorld {
	t.Helper()
	w := newIPWorld(t)
	w.h.eopts.BannerWait = 300 * time.Millisecond
	w.h.eopts.ConnectTimeout = 500 * time.Millisecond
	return w
}

// refused maps addr:port to loopback port 1, where nothing listens, so the connection is refused.
// (closedPort frees an ephemeral port, which a test running at the same time may take for a
// listener of its own before the probe dials it.)
func (w *ipWorld) refused(addr string, port int) {
	w.mapDial(addr, port, "127.0.0.1:1")
}

// closeAllBut refuses every built-in probe port of the address except the kept ones, so that the
// probes of the others are the only ones that find anything.
func (w *ipWorld) closeAllBut(addr string, keep ...int) {
	w.t.Helper()
	for _, p := range ipProbePorts {
		if !slices.Contains(keep, p) {
			w.refused(addr, p)
		}
	}
}

// blackhole maps addr:port to a loopback port whose accept queue is full, so a connection attempt
// is not answered at all. The test is skipped where the system does not behave so.
func (w *ipWorld) blackhole(addr string, port int) {
	w.t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		w.t.Skipf("no raw socket: %v", err)
	}
	w.t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		w.t.Skipf("bind: %v", err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		w.t.Skipf("listen: %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	in4, ok := sa.(*syscall.SockaddrInet4)
	if err != nil || !ok {
		w.t.Skipf("getsockname: %v", err)
	}
	to := net.JoinHostPort("127.0.0.1", fmt.Sprint(in4.Port))
	for range 5 { // fill the queue, which holds at most a connection or two
		c, err := net.DialTimeout("tcp", to, 200*time.Millisecond)
		if err != nil {
			break
		}
		w.t.Cleanup(func() { c.Close() })
	}
	if c, err := net.DialTimeout("tcp", to, 200*time.Millisecond); err == nil {
		c.Close()
		w.t.Skip("this system accepts connections on a full queue")
	}
	w.mapDial(addr, port, to)
}

// resetServer maps addr:port to a listener that resets every connection as soon as it is made.
func (w *ipWorld) resetServer(addr string, port int) {
	w.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			c.Close()
		}
	}()
	w.mapDial(addr, port, ln.Addr().String())
}

// activeCert is a self-signed certificate: its issuer is its subject, the common name given.
func activeCert(t *testing.T, issuer string, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: issuer},
		NotBefore: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: notAfter,
		DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// activeServer is an HTTP or HTTPS server that records the server name of every TLS handshake and
// the method, path and Host of every request.
type activeServer struct {
	*ipTarget
	mu     sync.Mutex
	hellos []string
	reqs   []activeRequest
}

type activeRequest struct{ Method, Path, Host string }

// sni is the server name each handshake offered, sorted ("" for none).
func (s *activeServer) sni() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.hellos)
	sort.Strings(out)
	return out
}

// requests are the requests received.
func (s *activeServer) requests() []activeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

// hosts are the Host of each request received, sorted, without any port.
func (s *activeServer) hosts() []string {
	var out []string
	for _, r := range s.requests() {
		h := r.Host
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		out = append(out, strings.Trim(h, "[]"))
	}
	sort.Strings(out)
	return out
}

// activeServe maps addr:port to an HTTPS server with the certificate, or to an HTTP server when cert
// is nil. h answers the requests: a 200 "ok" when it is nil.
func (w *ipWorld) activeServe(addr string, port int, cert *tls.Certificate, h http.HandlerFunc) *activeServer {
	w.t.Helper()
	if h == nil {
		h = func(rw http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(rw, "ok") }
	}
	s := &activeServer{ipTarget: &ipTarget{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, activeRequest{r.Method, r.URL.Path, r.Host})
		s.mu.Unlock()
		h(rw, r)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.conns.Add(1)
		}
	}
	if cert != nil {
		srv.TLS = &tls.Config{
			Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
				s.mu.Lock()
				s.hellos = append(s.hellos, hi.ServerName)
				s.mu.Unlock()
				return nil, nil
			},
		}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	s.close = srv.Close
	w.t.Cleanup(srv.Close)
	w.mapDial(addr, port, srv.Listener.Addr().String())
	w.target(addr, port, s.ipTarget)
	return s
}

// activeEntry is one entry of a record's ports, tls or web list: its keys in the order written, and
// its values.
type activeEntry struct {
	keys []string
	m    map[string]any
}

func (e activeEntry) port() int           { f, _ := e.m["port"].(float64); return int(f) }
func (e activeEntry) str(k string) string { s, _ := e.m[k].(string); return s }
func (e activeEntry) num(k string) int    { f, _ := e.m[k].(float64); return int(f) }
func (e activeEntry) strs(k string) []string {
	var out []string
	l, _ := e.m[k].([]any)
	for _, v := range l {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// activeEntries are the entries of the record's list at key (ports, tls or web), each checked for
// having exactly the wantKeys in order. A null list gives none.
func activeEntries(t *testing.T, r ipRecord, key string, wantKeys []string) []activeEntry {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(r.raw, &top); err != nil {
		t.Fatal(err)
	}
	raw, ok := top[key]
	if !ok {
		t.Fatalf("%s: no %s in %s", r.address(), key, r.raw)
	}
	if string(raw) == "null" {
		return nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("%s is not a list in %s: %v", key, r.raw, err)
	}
	var out []activeEntry
	for _, item := range list {
		e := activeEntry{keys: keysOf(t, item)}
		if !slices.Equal(e.keys, wantKeys) {
			t.Errorf("%s entry keys = %v, want %v", key, e.keys, wantKeys)
		}
		if err := json.Unmarshal(item, &e.m); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

var (
	activePortKeys = []string{"port", "state", "banner"}
	activeTLSKeys  = []string{"port", "server_name", "outcome", "names", "issuer", "expiry"}
	activeWebKeys  = []string{"port", "scheme", "host", "outcome", "status", "server", "title", "location"}
)

// activePorts are the record's ports by port number, failing the test on a port listed twice.
func activePorts(t *testing.T, r ipRecord) map[int]activeEntry {
	t.Helper()
	out := map[int]activeEntry{}
	for _, e := range activeEntries(t, r, "ports", activePortKeys) {
		if _, dup := out[e.port()]; dup {
			t.Errorf("port %d is listed twice in %s", e.port(), r.raw)
		}
		out[e.port()] = e
	}
	return out
}

// activeAt are the entries for a port.
func activeAt(es []activeEntry, port int) []activeEntry {
	var out []activeEntry
	for _, e := range es {
		if e.port() == port {
			out = append(out, e)
		}
	}
	return out
}

// activePortList are the sorted, distinct ports of the entries.
func activePortList(es []activeEntry) []int {
	var out []int
	for _, e := range es {
		out = append(out, e.port())
	}
	sort.Ints(out)
	return slices.Compact(out)
}

// sortedPorts is a sorted copy of the ports, without repeats.
func sortedPorts(ports ...[]int) []int {
	out := slices.Concat(ports...)
	sort.Ints(out)
	return slices.Compact(out)
}

// serverNames are the server_name of each entry, sorted; a null is "".
func activeServerNames(es []activeEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.str("server_name"))
	}
	sort.Strings(out)
	return out
}

// activeContacted are the ports of the address that accepted a connection.
func (w *ipWorld) activeContacted(addr string) []int {
	var out []int
	prefix := ipKey(addr, 0)
	prefix = strings.TrimSuffix(prefix, "0")
	for _, c := range w.contacted() {
		if rest, ok := strings.CutPrefix(c, prefix); ok {
			var p int
			_, _ = fmt.Sscan(rest, &p)
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// activeNoThirdParty fails the test if any third party was asked, or any public resolver was asked
// for a name of the addresses (their reverse names or Team Cymru's), as is the rule for a
// non-public address whether or not it is contacted.
func (w *ipWorld) activeNoThirdParty(addrs ...string) {
	w.t.Helper()
	if n := w.httpRequests(); n != 0 {
		w.t.Errorf("%d HTTP requests were made to third parties", n)
	}
	for _, a := range addrs {
		for _, n := range dnsNames(w.dns) {
			if strings.HasPrefix(n, reverseLabel(a)+".") {
				w.t.Errorf("the public resolvers were asked for %s", n)
			}
		}
	}
}

// ---- the keys ----

// The keys --active adds are absent without it and present with it, after reverse_ip_count and before
// failures. Without --active nothing is connected to.
func TestIPActive_KeysAreAddedOnlyUnderActive(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr)
	w.sealProbes([]string{addr})
	rec := w.record(addr)
	if !slices.Equal(rec.keys, ipDefaultKeys) {
		t.Errorf("default keys = %v", rec.keys)
	}
	rec = w.record(addr, "--fields", "all")
	if !slices.Equal(rec.keys, ipAllKeys(false)) {
		t.Errorf("--fields all keys = %v", rec.keys)
	}
	if c := w.contacted(); len(c) != 0 {
		t.Fatalf("connections without --active: %v", c)
	}
	w.closeAllBut(addr) // nothing answers: the keys are what matters here
	rec = w.record(addr, "--active")
	if !slices.Equal(rec.keys, ipAllKeys(true)) {
		t.Errorf("--active keys = %v, want %v", rec.keys, ipAllKeys(true))
	}
	if !rec.isNull("not_contacted") || !slices.Equal(rec.keys[len(rec.keys)-5:], []string{"not_contacted", "ports", "tls", "web", "failures"}) {
		t.Errorf("--active record %s", rec.raw)
	}
	rec = w.record(addr, "--active", "--fields", "all")
	if !slices.Equal(rec.keys, ipAllKeys(true)) {
		t.Errorf("--active --fields all keys = %v", rec.keys)
	}
}

// --active is the confirmation: no acknowledgement flag or setting is needed.
func TestIPActive_NeedsNoAcknowledgement(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr)
	w.listen(addr, 22, "SSH-2.0-OpenSSH_9.6\r\n")
	w.closeAllBut(addr, 22)
	rec := w.record(addr, "--active", "--fields", "ports")
	if p := activePorts(t, rec)[22]; p.str("state") != "open" {
		t.Errorf("port 22: %s", rec.raw)
	}
}

// ---- which ports ----

// A dedicated public address is probed on every built-in port and on InternetDB's other ports, with
// one TCP handshake each. Nothing is sent on any of them: the scan reads the unprompted banner and
// is not followed by a handshake or a request when only the ports are wanted.
func TestIPActive_ADedicatedAddressIsProbedOnTheBuiltInPortsAndInternetDBsOthers(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr, func(f *ipFacts) { f.Ports = []int{22, 2222, 3000} })
	w.sealProbes([]string{addr}, 2222, 3000)
	rec := w.record(addr, "--active", "--fields", "ports,not_contacted")
	want := sortedPorts(ipProbePorts, []int{2222, 3000})
	ports := activePorts(t, rec)
	var got []int
	for p, e := range ports {
		got = append(got, p)
		if e.str("state") != "open" {
			t.Errorf("port %d is %q, want open", p, e.str("state"))
		}
	}
	sort.Ints(got)
	if !slices.Equal(got, want) {
		t.Errorf("ports probed = %v, want %v", got, want)
	}
	if !rec.isNull("not_contacted") {
		t.Errorf("not_contacted = %v", rec.m["not_contacted"])
	}
	if f := rec.failures(); len(f) != 0 {
		t.Errorf("failures %+v", f)
	}
	if c := w.activeContacted(addr); !slices.Equal(c, want) {
		t.Errorf("connections to %v, want %v", c, want)
	}
	for _, p := range want {
		if tgt := w.targetAt(addr, p); tgt.connections() != 1 || tgt.received() != 0 {
			t.Errorf("port %d: %d connections and %d bytes received, want one connection and none", p, tgt.connections(), tgt.received())
		}
	}
}

// A public IPv6 address is probed on the same ports.
func TestIPActive_AnIPv6AddressIsProbedToo(t *testing.T) {
	t.Parallel()
	const addr = "2001:4860:4860::8888"
	w := activeWorld(t)
	w.seed(addr)
	w.listen(addr, 22, "SSH-2.0-OpenSSH_9.6\r\n")
	w.closeAllBut(addr, 22)
	rec := w.record(addr, "--active", "--fields", "ports,not_contacted")
	ports := activePorts(t, rec)
	if len(ports) != len(ipProbePorts) || ports[22].str("state") != "open" || ports[22].str("banner") != "SSH-2.0-OpenSSH_9.6\r\n" || ports[21].str("state") != "closed" {
		t.Errorf("record %s", rec.raw)
	}
	if !rec.isNull("not_contacted") {
		t.Errorf("not_contacted = %v", rec.m["not_contacted"])
	}
}

// The ports InternetDB reports beyond the built-in list are probed lowest first, at most 64 of them:
// with 80 beyond the list, the 64 lowest.
func TestIPActive_InternetDBPortsBeyondTheBuiltInListAreCappedAtTheLowest64(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	var high []int // 20079 down to 20000, then a low port, and a built-in one
	for p := 20079; p >= 20000; p-- {
		high = append(high, p)
	}
	w.seed(addr, func(f *ipFacts) { f.Ports = slices.Concat(high, []int{7, 22}) })
	extras := slices.Concat([]int{7}, high)
	w.sealProbes([]string{addr}, extras...)
	rec := w.record(addr, "--active", "--fields", "ports")
	want := sortedPorts(ipProbePorts, []int{7}, high[len(high)-63:]) // 7 and 20000..20062
	if got := activePortList(activeEntries(t, rec, "ports", activePortKeys)); !slices.Equal(got, want) {
		t.Errorf("ports probed = %v, want %v", got, want)
	}
	if len(want) != len(ipProbePorts)+64 {
		t.Fatalf("test is wrong: %d ports", len(want))
	}
	for _, p := range high[:17] { // 20079 .. 20063
		if n := w.targetAt(addr, p).connections(); n != 0 {
			t.Errorf("port %d was connected to %d times", p, n)
		}
	}
	for _, p := range []int{7, 20000, 20062} {
		if n := w.targetAt(addr, p).connections(); n != 1 {
			t.Errorf("port %d was connected to %d times, want 1", p, n)
		}
	}
}

// Each port is open, closed or without an answer. The banner is the bytes the service sent
// unprompted, as text with any invalid UTF-8 replaced, at most 1024 bytes; nothing is sent to the
// service.
func TestIPActive_PortStatesAndBanners(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr)
	w.sealProbes([]string{addr})
	w.refused(addr, 21)
	w.blackhole(addr, 23)
	ssh := w.listen(addr, 22, "SSH-2.0-OpenSSH_9.6\r\n")
	silent := w.listen(addr, 25, "")
	pop := w.listen(addr, 110, "\xff\xfe+OK ready\r\n")
	imap := w.listen(addr, 143, strings.Repeat("A", 2000))
	rec := w.record(addr, "--active", "--fields", "ports")
	ports := activePorts(t, rec)
	for port, state := range map[int]string{21: "closed", 22: "open", 23: "no-answer", 25: "open", 110: "open", 143: "open", 389: "open"} {
		if got := ports[port].str("state"); got != state {
			t.Errorf("port %d is %q, want %q", port, got, state)
		}
	}
	if got := ports[22].str("banner"); got != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Errorf("port 22 banner %q", got)
	}
	if got := ports[25].str("banner"); got != "" {
		t.Errorf("port 25 banner %q, want none", got)
	}
	if got := ports[110].str("banner"); !utf8.ValidString(got) || !strings.Contains(got, "+OK ready") || !strings.Contains(got, "�") {
		t.Errorf("port 110 banner %q, want the invalid bytes replaced", got)
	}
	if got := ports[143].str("banner"); len(got) == 0 || len(got) > 1024 || strings.Trim(got, "A") != "" {
		t.Errorf("port 143 banner has %d bytes", len(got))
	}
	if got := ports[21].str("banner"); got != "" {
		t.Errorf("a closed port has the banner %q", got)
	}
	for _, tgt := range []*ipTarget{ssh, silent, pop, imap} {
		if tgt.connections() != 1 || tgt.received() != 0 {
			t.Errorf("port %d: %d connections and %d bytes received, want one and none", tgt.Port, tgt.connections(), tgt.received())
		}
	}
	if f := rec.failures(); len(f) != 0 {
		t.Errorf("failures %+v: a port that does not answer is a result", f)
	}
}

// ---- which addresses ----

// An address of shared provider infrastructure is not contacted, and its record says why.
func TestIPActive_SharedProviderAddressIsNotContacted(t *testing.T) { // mutation target
	t.Parallel()
	const addr = "104.16.0.1"
	w := activeWorld(t)
	w.seed(addr, ipCloudflare...)
	w.sealProbes([]string{addr})
	rec := w.record(addr, "--active")
	if got, want := rec.str("not_contacted"), "shared provider infrastructure (cloudflare, cdn)"; got != want {
		t.Errorf("not_contacted = %q, want %q", got, want)
	}
	for _, k := range []string{"ports", "tls", "web"} {
		if !rec.emptyValue(k) {
			t.Errorf("%s = %v, want none", k, rec.m[k])
		}
	}
	if c := w.contacted(); len(c) != 0 {
		t.Errorf("connections to %v", c)
	}
	if w.h.network() != 0 {
		t.Error("a network canary was hit")
	}
	if w.dns.Count(cymruOriginName(addr), "TXT") == 0 {
		t.Error("the owner was not asked of Team Cymru")
	}
}

// A cloud (hyperscaler) address is not shared infrastructure: it is contacted. So is a
// DigitalOcean one.
func TestIPActive_CloudAddressesAreContacted(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, addr string
		mods       []func(*ipFacts)
	}{
		{"aws", "52.95.110.1", ipAWS},
		{"digitalocean", "143.110.150.2", ipDigitalOcn},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := activeWorld(t)
			w.seed(c.addr, c.mods...)
			w.listen(c.addr, 22, "SSH-2.0-OpenSSH_9.6\r\n")
			w.closeAllBut(c.addr, 22)
			rec := w.record(c.addr, "--active")
			if !rec.isNull("not_contacted") || activePorts(t, rec)[22].str("state") != "open" {
				t.Errorf("record %s", rec.raw)
			}
			if rec.str("provider_class") != "hyperscaler" {
				t.Errorf("provider_class = %q", rec.str("provider_class"))
			}
			if w.targetAt(c.addr, 22).connections() != 1 {
				t.Errorf("port 22 was connected to %d times", w.targetAt(c.addr, 22).connections())
			}
		})
	}
}

// An owner that Team Cymru answers it does not know is not a failure, and the address is contacted.
func TestIPActive_AnAddressWithNoKnownOwnerIsContacted(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr, func(f *ipFacts) { f.ASN, f.ASName, f.ASPrefix = 0, "", "" }) // Team Cymru has no answer
	w.listen(addr, 22, "SSH-2.0-OpenSSH_9.6\r\n")
	w.closeAllBut(addr, 22)
	rec := w.record(addr, "--active")
	if !rec.isNull("not_contacted") || activePorts(t, rec)[22].str("state") != "open" {
		t.Errorf("record %s", rec.raw)
	}
}

// A public address whose owner could not be found, because Team Cymru failed, is not contacted: it
// might be shared infrastructure.
func TestIPActive_AFailedOwnerLookupMeansNotContacted(t *testing.T) { // mutation target
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr)
	w.dns.Rcode(cymruOriginName(addr), int(mdns.RcodeServerFailure))
	w.sealProbes([]string{addr})
	env, _ := w.partial(addr, "--active")
	if len(env.Records) != 1 {
		t.Fatalf("records %v", env.addresses())
	}
	rec := env.Records[0]
	if got, want := rec.str("not_contacted"), "owner unknown: cymru NETWORK_ERROR"; got != want {
		t.Errorf("not_contacted = %q, want %q", got, want)
	}
	if f := rec.failureOf("cymru"); f.Code != "NETWORK_ERROR" || !f.Transient {
		t.Errorf("failure %+v", f)
	}
	if c := w.contacted(); len(c) != 0 {
		t.Errorf("connections to %v", c)
	}
	for _, k := range []string{"ports", "tls", "web"} {
		if !rec.emptyValue(k) {
			t.Errorf("%s = %v, want none", k, rec.m[k])
		}
	}
}

// A non-public address that only the public resolvers gave for a hostname is not contacted: a hostile
// name could otherwise point the probes at the operator's own network. Its record says why.
func TestIPActive_ANonPublicAddressFromPublicDNSIsNotContacted(t *testing.T) { // mutation target
	t.Parallel()
	w := activeWorld(t)
	w.dns.A("internal.example.com", "10.1.2.3")
	w.dns.A("metadata.example.com", "169.254.169.254")
	w.local.PTR("10.1.2.3", "gw.corp.example")
	addrs := []string{"10.1.2.3", "169.254.169.254"}
	w.sealProbes(addrs)
	env := w.lookup("internal.example.com", "metadata.example.com", "--active")
	if len(env.Records) != 2 {
		t.Fatalf("records %v", env.addresses())
	}
	for i, rec := range env.Records {
		if got := rec.str("not_contacted"); got != "non-public address from public DNS" {
			t.Errorf("%s: not_contacted = %q", addrs[i], got)
		}
		if rec.address() != addrs[i] || rec.str("kind") == "public" {
			t.Errorf("record %s", rec.raw)
		}
		for _, k := range []string{"ports", "tls", "web"} {
			if !rec.emptyValue(k) {
				t.Errorf("%s: %s = %v, want none", addrs[i], k, rec.m[k])
			}
		}
	}
	if c := w.contacted(); len(c) != 0 {
		t.Errorf("connections to %v", c)
	}
	w.activeNoThirdParty(addrs...)
}

// The same non-public address is contacted when it was given as a literal or in a CIDR, or when this
// machine's resolver gave it (a single-label name, or a name the public resolvers do not know); and a
// literal and a name from public DNS for one address make it a literal's.
func TestIPActive_ANonPublicAddressIsContactedWhenNotOnlyPublicDNSGaveIt(t *testing.T) { // mutation target
	t.Parallel()
	const banner = "SSH-2.0-OpenSSH_9.6\r\n"
	for _, c := range []struct {
		name      string
		args      []string
		addrs     []string
		hostnames []string
		prepare   func(w *ipWorld)
	}{
		{"a literal", []string{"10.1.2.3"}, []string{"10.1.2.3"}, nil, func(*ipWorld) {}},
		{"a CIDR", []string{"10.9.9.0/30"}, []string{"10.9.9.0", "10.9.9.1", "10.9.9.2", "10.9.9.3"}, nil, func(*ipWorld) {}},
		{"a single-label name", []string{"intranet"}, []string{"10.1.2.4"}, []string{"intranet"},
			func(w *ipWorld) { w.local.A("intranet", "10.1.2.4") }},
		{"a name the public resolvers do not know", []string{"corp.example.com"}, []string{"10.1.2.5"}, []string{"corp.example.com"},
			func(w *ipWorld) { w.local.A("corp.example.com", "10.1.2.5") }},
		{"a literal and a name from public DNS", []string{"10.1.2.3", "internal.example.com"}, []string{"10.1.2.3"}, []string{"internal.example.com"},
			func(w *ipWorld) { w.dns.A("internal.example.com", "10.1.2.3") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := activeWorld(t)
			c.prepare(w)
			for _, a := range c.addrs {
				w.listen(a, 22, banner)
				w.closeAllBut(a, 22)
			}
			env := w.lookup(append(slices.Clone(c.args), "--active")...)
			if !slices.Equal(env.addresses(), c.addrs) {
				t.Fatalf("addresses %v, want %v", env.addresses(), c.addrs)
			}
			for _, rec := range env.Records {
				if !rec.isNull("not_contacted") || activePorts(t, rec)[22].str("banner") != banner {
					t.Errorf("record %s", rec.raw)
				}
				if got := rec.strs("hostnames"); !slices.Equal(got, c.hostnames) && len(c.hostnames) != 0 {
					t.Errorf("hostnames %v, want %v", got, c.hostnames)
				}
				if n := w.targetAt(rec.address(), 22).connections(); n != 1 {
					t.Errorf("%s: port 22 was connected to %d times", rec.address(), n)
				}
			}
			w.activeNoThirdParty(c.addrs...)
		})
	}
}

// A non-public address is sent to no third party and to no public resolver even when it is
// contacted: its PTR goes to this machine's resolver only.
func TestIPActive_AContactedNonPublicAddressIsSentToNoThirdParty(t *testing.T) {
	t.Parallel()
	w := activeWorld(t)
	addrs := []string{"10.1.2.3", "100.64.0.9", "fd00::1", "192.168.0.7"}
	for _, a := range addrs {
		w.seed(a) // every public source would have an answer
		w.local.PTR(a, "host."+strings.NewReplacer(".", "-", ":", "-").Replace(a)+".corp.example")
		w.listen(a, 22, "SSH-2.0-OpenSSH_9.6\r\n")
		w.closeAllBut(a, 22)
	}
	env := w.lookup(append(slices.Clone(addrs), "--active")...)
	for _, rec := range env.Records {
		if !rec.isNull("not_contacted") || activePorts(t, rec)[22].str("state") != "open" || len(rec.strs("ptr")) != 1 {
			t.Errorf("record %s", rec.raw)
		}
	}
	if w.httpRequests() != 0 || w.dns.Total() != 0 {
		t.Errorf("HTTP requests %d, public queries %v", w.httpRequests(), dnsNames(w.dns))
	}
	sawOnly(t, w.local, "PTR", reverseName("10.1.2.3"), reverseName("100.64.0.9"), reverseName("fd00::1"), reverseName("192.168.0.7"))
}

// An unspecified, this-network, multicast or broadcast address is never connected to, and nor is an
// IPv6 link-local address, which needs a zone. The record says why.
func TestIPActive_UnreachableKindsAreNeverDialled(t *testing.T) { // mutation target
	t.Parallel()
	w := activeWorld(t)
	addrs := []string{"0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255", "fe80::1", "::", "ff02::1"}
	w.sealProbes(addrs)
	env := w.lookup(append(slices.Clone(addrs), "--active")...)
	if !slices.Equal(env.addresses(), addrs) {
		t.Fatalf("addresses %v", env.addresses())
	}
	for _, rec := range env.Records {
		if rec.str("not_contacted") == "" {
			t.Errorf("%s: not_contacted = %v, want the reason", rec.address(), rec.m["not_contacted"])
		}
		if rec.address() == "fe80::1" && !strings.Contains(rec.str("not_contacted"), "zone") {
			t.Errorf("fe80::1: not_contacted = %q, want it to say a zone is needed", rec.str("not_contacted"))
		}
		for _, k := range []string{"ports", "tls", "web"} {
			if !rec.emptyValue(k) {
				t.Errorf("%s: %s = %v, want none", rec.address(), k, rec.m[k])
			}
		}
	}
	if c := w.contacted(); len(c) != 0 {
		t.Errorf("connections to %v", c)
	}
	w.activeNoThirdParty(addrs...)
}

// Every other non-public kind is contacted: loopback, link-local IPv4, CGNAT, documentation and
// unique-local addresses.
func TestIPActive_OtherNonPublicKindsAreContacted(t *testing.T) {
	t.Parallel()
	w := activeWorld(t)
	addrs := []string{"127.0.0.1", "::1", "169.254.1.1", "100.64.0.1", "192.0.2.1", "fd00::1"}
	for _, a := range addrs {
		w.listen(a, 22, "SSH-2.0-OpenSSH_9.6\r\n")
		w.closeAllBut(a, 22)
	}
	env := w.lookup(append(slices.Clone(addrs), "--active", "--fields", "ports,not_contacted")...)
	for _, rec := range env.Records {
		if !rec.isNull("not_contacted") || activePorts(t, rec)[22].str("state") != "open" {
			t.Errorf("%s: %s", rec.address(), rec.raw)
		}
	}
}

// ---- TLS and web ----

// activeHost is a request's Host without its port.
func activeHost(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		return h
	}
	return r.Host
}

// Two hostnames on one address give two handshakes on each open TLS port, each with its own hostname
// as the server name (as the server saw it), and the handshake is all that is sent: no request.
func TestIPActive_TLSIsHandshakenOncePerHostnameWithItsServerName(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.dns.A("a.example.org", addr)
	w.dns.A("b.example.org", addr)
	w.seed(addr)
	cert := activeCert(t, "nyx test issuer", time.Date(2031, 3, 4, 23, 30, 0, 0, time.UTC), "a.example.org", "b.example.org")
	tlsSrv := w.activeServe(addr, 443, &cert, nil)
	httpSrv := w.activeServe(addr, 80, nil, nil)
	w.activeServe(addr, 8443, &cert, nil)
	w.activeServe(addr, 993, &cert, nil)
	w.closeAllBut(addr, 80, 443, 993, 8443)
	rec := w.record("a.example.org", "b.example.org", "--active", "--fields", "tls")
	if want := ipExpectKeys("tls"); !slices.Equal(rec.keys, want) {
		t.Fatalf("keys %v, want %v", rec.keys, want)
	}
	if got := rec.strs("hostnames"); !slices.Equal(got, []string{"a.example.org", "b.example.org"}) {
		t.Errorf("hostnames %v", got)
	}
	entries := activeEntries(t, rec, "tls", activeTLSKeys)
	for _, p := range []int{443, 993, 8443} {
		if names := activeServerNames(activeAt(entries, p)); !slices.Equal(names, []string{"a.example.org", "b.example.org"}) {
			t.Errorf("port %d: server names %v, want each hostname once", p, names)
		}
	}
	if len(entries) != 6 {
		t.Errorf("%d tls entries, want 6 (two hostnames on each of the three open TLS ports)", len(entries))
	}
	for _, e := range activeAt(entries, 443) {
		if e.str("outcome") != "ok" {
			t.Errorf("port 443, %s: outcome %q", e.str("server_name"), e.str("outcome"))
		}
	}
	if got := tlsSrv.sni(); !slices.Equal(got, []string{"a.example.org", "b.example.org"}) {
		t.Errorf("the server on 443 saw the server names %v", got)
	}
	if n := len(tlsSrv.requests()) + len(httpSrv.requests()); n != 0 {
		t.Errorf("--fields tls sent %d requests", n)
	}
}

// With no input hostname there is one handshake without a server name, and one GET with the address
// as the Host.
func TestIPActive_WithNoHostnameTheHandshakeHasNoServerNameAndTheGETHasTheAddress(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr)
	cert := activeCert(t, "nyx test issuer", time.Date(2031, 3, 4, 23, 30, 0, 0, time.UTC), "a.example.org")
	tlsSrv := w.activeServe(addr, 443, &cert, nil)
	httpSrv := w.activeServe(addr, 80, nil, nil)
	w.closeAllBut(addr, 80, 443)
	rec := w.record(addr, "--active", "--fields", "tls,web")
	tlsEntries := activeEntries(t, rec, "tls", activeTLSKeys)
	if got := activeAt(tlsEntries, 443); len(tlsEntries) != 1 || len(got) != 1 || got[0].str("server_name") != "" {
		t.Errorf("tls %v, want one entry, on 443, without a server name", rec.m["tls"])
	}
	if e := activeAt(tlsEntries, 443); len(e) == 1 && (e[0].str("outcome") != "ok" || e[0].m["server_name"] != nil && e[0].str("server_name") != "") {
		t.Errorf("tls 443: %v", e[0].m)
	}
	webEntries := activeEntries(t, rec, "web", activeWebKeys)
	for _, p := range []int{80, 443} {
		got := activeAt(webEntries, p)
		if len(got) != 1 || got[0].str("host") != addr {
			t.Errorf("web port %d: %v, want one entry with the address as host", p, got)
		}
	}
	if len(webEntries) != 2 {
		t.Errorf("web %v, want entries for 80 and 443 only", rec.m["web"])
	}
	for _, h := range tlsSrv.sni() {
		if h != "" {
			t.Errorf("a handshake offered the server name %q", h)
		}
	}
	if got := httpSrv.hosts(); !slices.Equal(got, []string{addr}) {
		t.Errorf("the HTTP server saw the hosts %v", got)
	}
	if got := tlsSrv.hosts(); !slices.Equal(got, []string{addr}) {
		t.Errorf("the HTTPS server saw the hosts %v", got)
	}
}

// Two hostnames on one address give one GET each on every open web port, with the hostname as the
// Host, and a web entry each; the scheme is https on a TLS port and http on the others.
func TestIPActive_GETIsSentOncePerHostnameWithItsHost(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.dns.A("a.example.org", addr)
	w.dns.A("b.example.org", addr)
	w.seed(addr)
	page := func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Server", "nginx/1.25.3")
		_, _ = fmt.Fprintf(rw, "<html><head><title>Site of %s</title></head><body></body></html>", activeHost(r))
	}
	cert := activeCert(t, "nyx test issuer", time.Date(2031, 3, 4, 23, 30, 0, 0, time.UTC), "a.example.org", "b.example.org")
	servers := map[int]*activeServer{
		80: w.activeServe(addr, 80, nil, page), 8080: w.activeServe(addr, 8080, nil, page),
		443: w.activeServe(addr, 443, &cert, page), 8443: w.activeServe(addr, 8443, &cert, page),
	}
	w.closeAllBut(addr, 80, 8080, 443, 8443)
	rec := w.record("a.example.org", "b.example.org", "--active", "--fields", "web")
	if want := ipExpectKeys("web"); !slices.Equal(rec.keys, want) {
		t.Fatalf("keys %v, want %v", rec.keys, want)
	}
	entries := activeEntries(t, rec, "web", activeWebKeys)
	if len(entries) != 8 {
		t.Errorf("%d web entries, want 8 (two hostnames on each of the four open web ports)", len(entries))
	}
	for port, srv := range servers {
		wantScheme := "http"
		if slices.Contains(ipTLSPorts, port) {
			wantScheme = "https"
		}
		got := activeAt(entries, port)
		if hosts := func() []string {
			var h []string
			for _, e := range got {
				h = append(h, e.str("host"))
			}
			sort.Strings(h)
			return h
		}(); !slices.Equal(hosts, []string{"a.example.org", "b.example.org"}) {
			t.Errorf("port %d: hosts %v", port, hosts)
		}
		for _, e := range got {
			if e.str("scheme") != wantScheme || e.str("outcome") != "ok" || e.num("status") != 200 ||
				e.str("server") != "nginx/1.25.3" || e.str("title") != "Site of "+e.str("host") {
				t.Errorf("port %d: %v", port, e.m)
			}
		}
		if hosts := srv.hosts(); !slices.Equal(hosts, []string{"a.example.org", "b.example.org"}) {
			t.Errorf("the server on %d saw the hosts %v, want each once", port, hosts)
		}
		for _, r := range srv.requests() {
			if r.Method != http.MethodGet || r.Path != "/" {
				t.Errorf("the server on %d was sent %s %s", port, r.Method, r.Path)
			}
		}
	}
}

// A TLS entry has the certificate's names, its issuer and its expiry as a date in UTC, and the
// handshake succeeded whether or not the certificate is trusted: an expired one with other names is
// recorded as it is.
func TestIPActive_TLSEntryHasTheCertificatesNamesIssuerAndExpiry(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.dns.A("a.example.org", addr)
	w.seed(addr)
	good := activeCert(t, "nyx test issuer", time.Date(2031, 3, 4, 23, 30, 0, 0, time.UTC), "a.example.org", "www.example.org")
	expired := activeCert(t, "nyx old issuer", time.Date(2019, 5, 6, 0, 30, 0, 0, time.UTC), "other.example.net")
	w.activeServe(addr, 443, &good, nil)
	w.activeServe(addr, 8443, &expired, nil)
	w.closeAllBut(addr, 443, 8443)
	rec := w.record("a.example.org", "--active", "--fields", "tls")
	entries := activeEntries(t, rec, "tls", activeTLSKeys)
	if len(entries) != 2 {
		t.Fatalf("tls entries %v", rec.m["tls"])
	}
	for _, c := range []struct {
		port           int
		names          []string
		issuer, expiry string
	}{
		{443, []string{"a.example.org", "www.example.org"}, "nyx test issuer", "2031-03-04"},
		{8443, []string{"other.example.net"}, "nyx old issuer", "2019-05-06"},
	} {
		e := activeAt(entries, c.port)[0]
		names := e.strs("names")
		sort.Strings(names)
		if e.str("outcome") != "ok" || e.str("server_name") != "a.example.org" || !slices.Equal(names, c.names) ||
			!strings.Contains(e.str("issuer"), c.issuer) || e.str("expiry") != c.expiry {
			t.Errorf("port %d: %v", c.port, e.m)
		}
	}
}

// A web entry has the status, the Server header, the page's title and the Location. A redirect is
// reported and not followed: its target is not asked.
func TestIPActive_WebEntryHasStatusServerTitleAndLocationAndARedirectIsNotFollowed(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr)
	var landed int
	var mu sync.Mutex
	counted := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		landed++
		mu.Unlock()
		_, _ = io.WriteString(rw, "landed")
	}))
	t.Cleanup(counted.Close)
	w.activeServe(addr, 8080, nil, func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Server", "nginx/1.25.3")
		_, _ = io.WriteString(rw, "<html><head><title>Example Site</title></head><body>hello</body></html>")
	})
	redirecting := w.activeServe(addr, 8000, nil, func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Server", "Apache/2.4.58")
		rw.Header().Set("Location", counted.URL+"/landing")
		rw.WriteHeader(http.StatusFound)
	})
	w.activeServe(addr, 8888, nil, func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
	})
	w.closeAllBut(addr, 8080, 8000, 8888)
	rec := w.record(addr, "--active", "--fields", "web")
	entries := activeEntries(t, rec, "web", activeWebKeys)
	if len(entries) != 3 {
		t.Fatalf("web entries %v", rec.m["web"])
	}
	ok := activeAt(entries, 8080)[0]
	if ok.str("scheme") != "http" || ok.str("host") != addr || ok.str("outcome") != "ok" || ok.num("status") != 200 ||
		ok.str("server") != "nginx/1.25.3" || ok.str("title") != "Example Site" || ok.str("location") != "" {
		t.Errorf("port 8080: %v", ok.m)
	}
	redir := activeAt(entries, 8000)[0]
	if redir.str("outcome") != "ok" || redir.num("status") != 302 || redir.str("server") != "Apache/2.4.58" ||
		redir.str("location") != counted.URL+"/landing" || redir.str("title") != "" {
		t.Errorf("port 8000: %v", redir.m)
	}
	if n := len(redirecting.requests()); n != 1 {
		t.Errorf("the redirecting server was sent %d requests, want 1", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if landed != 0 {
		t.Errorf("the redirect target was sent %d requests: a redirect is reported, not followed", landed)
	}
	if nf := activeAt(entries, 8888)[0]; nf.num("status") != 404 || nf.str("outcome") != "ok" {
		t.Errorf("port 8888: %v", nf.m)
	}
}

// A handshake is made only on an open built-in TLS port, and a GET is sent only on an open built-in
// web port, whatever else is open: not on a port InternetDB reported that speaks TLS or HTTP, nor
// on a built-in port that is neither. A closed port gets neither.
func TestIPActive_HandshakeAndGETAreSentOnlyOnOpenBuiltInPorts(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.dns.A("a.example.org", addr)
	w.seed(addr, func(f *ipFacts) { f.Ports = []int{443, 3000, 8444} })
	cert := activeCert(t, "nyx test issuer", time.Date(2031, 3, 4, 23, 30, 0, 0, time.UTC), "a.example.org")
	tlsOnly := w.activeServe(addr, 465, &cert, nil)        // a TLS port that is not a web port
	both := w.activeServe(addr, 8443, &cert, nil)          // a TLS port and a web port
	plainWeb := w.activeServe(addr, 8000, nil, nil)        // a web port that is not a TLS port
	notBuiltInTLS := w.activeServe(addr, 8444, &cert, nil) // InternetDB's, speaks TLS and HTTP
	notBuiltInWeb := w.activeServe(addr, 3000, nil, nil)   // InternetDB's, speaks HTTP
	notWeb := w.activeServe(addr, 9200, nil, nil)          // built in, speaks HTTP, is not a web port
	w.closeAllBut(addr, 465, 8443, 8000, 9200)
	w.refused(addr, 993) // a TLS port nothing listens on
	rec := w.record("a.example.org", "--active", "--fields", "ports,tls,web")
	ports := activePorts(t, rec)
	for port, state := range map[int]string{465: "open", 8443: "open", 8000: "open", 8444: "open", 3000: "open", 9200: "open", 993: "closed", 443: "closed"} {
		if ports[port].str("state") != state {
			t.Errorf("port %d is %q, want %q", port, ports[port].str("state"), state)
		}
	}
	if got, want := activePortList(activeEntries(t, rec, "tls", activeTLSKeys)), []int{465, 8443}; !slices.Equal(got, want) {
		t.Errorf("handshakes on %v, want %v", got, want)
	}
	if got, want := activePortList(activeEntries(t, rec, "web", activeWebKeys)), []int{8000, 8443}; !slices.Equal(got, want) {
		t.Errorf("GETs on %v, want %v", got, want)
	}
	for _, e := range activeEntries(t, rec, "web", activeWebKeys) {
		if want := map[int]string{8000: "http", 8443: "https"}[e.port()]; e.str("scheme") != want {
			t.Errorf("port %d: scheme %q, want %q", e.port(), e.str("scheme"), want)
		}
	}
	// The HTTPS server's handshakes include the one of the GET itself.
	for _, s := range []struct {
		name           string
		srv            *activeServer
		minSNI, maxSNI int
		reqs           int
	}{
		{"465", tlsOnly, 1, 1, 0}, {"8443", both, 1, 2, 1}, {"8000", plainWeb, 0, 0, 1},
		{"8444", notBuiltInTLS, 0, 0, 0}, {"3000", notBuiltInWeb, 0, 0, 0}, {"9200", notWeb, 0, 0, 0},
	} {
		if n := len(s.srv.sni()); n < s.minSNI || n > s.maxSNI || len(s.srv.requests()) != s.reqs {
			t.Errorf("port %s: %d handshakes and %d requests, want %d-%d and %d", s.name, n, len(s.srv.requests()), s.minSNI, s.maxSNI, s.reqs)
		}
		if s.srv.connections() < 1 {
			t.Errorf("port %s: never connected to", s.name)
		}
	}
}

// A plain server on a TLS port gives the outcome not-tls, and nothing listening on a port is closed
// and gets no handshake.
func TestIPActive_APlainServerOnATLSPortIsNotTLS(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr)
	w.activeServe(addr, 443, nil, nil)
	w.closeAllBut(addr, 443)
	rec := w.record(addr, "--active", "--fields", "ports,tls,web")
	tlsEntries := activeEntries(t, rec, "tls", activeTLSKeys)
	if len(tlsEntries) != 1 || tlsEntries[0].port() != 443 || tlsEntries[0].str("outcome") != "not-tls" {
		t.Errorf("tls %v", rec.m["tls"])
	} else if len(tlsEntries[0].strs("names")) != 0 || tlsEntries[0].str("issuer") != "" || tlsEntries[0].str("expiry") != "" {
		t.Errorf("an entry without a certificate has one: %v", tlsEntries[0].m)
	}
	for _, e := range activeEntries(t, rec, "web", activeWebKeys) {
		if e.port() != 443 || e.str("scheme") != "https" || (e.str("outcome") != "not-tls" && e.str("outcome") != "reset") {
			t.Errorf("web %v", e.m)
		}
	}
	if ports := activePorts(t, rec); ports[443].str("state") != "open" || ports[993].str("state") != "closed" {
		t.Errorf("ports %v", rec.m["ports"])
	}
	if f := rec.failures(); len(f) != 0 {
		t.Errorf("failures %+v", f)
	}
}

// What a probe finds (nothing answering, a service that is not TLS, a reset connection, a closed
// port) is a result: the call succeeds and nothing is a failure.
func TestIPActive_ProbeOutcomesAreResultsNeverFailures(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr, func(f *ipFacts) { f.Ports = []int{22, 80, 443, 8443} })
	w.activeServe(addr, 443, nil, nil) // not TLS
	w.listen(addr, 25, "")             // silent
	w.listen(addr, 993, "")            // silent, and closes on a handshake
	w.closeAllBut(addr, 443, 25, 993)
	w.blackhole(addr, 22)     // no answer
	w.resetServer(addr, 8443) // reset
	w.refused(addr, 80)
	rec := w.record(addr, "--active") // exit 0
	ports := activePorts(t, rec)
	for port, state := range map[int]string{22: "no-answer", 80: "closed", 25: "open", 443: "open", 993: "open"} {
		if got := ports[port].str("state"); got != state {
			t.Errorf("port %d is %q, want %q", port, got, state)
		}
	}
	if got := ports[8443].str("state"); got != "open" && got != "closed" && got != "no-answer" { // a reset before the handshake completes looks like no answer
		t.Errorf("port 8443 (reset) is %q", got)
	}
	for _, e := range activeEntries(t, rec, "tls", activeTLSKeys) {
		if e.str("outcome") == "ok" || e.str("outcome") == "" {
			t.Errorf("tls %v", e.m)
		}
	}
	if f := rec.failures(); len(f) != 0 {
		t.Errorf("failures %+v", f)
	}
}

// Each address has its own probes: a hostname's handshake and GET go only to the address it gave.
func TestIPActive_EachAddressIsProbedWithOnlyItsOwnHostnames(t *testing.T) {
	t.Parallel()
	w := activeWorld(t)
	w.dns.A("a.example.org", "93.184.216.34")
	w.dns.A("b.example.org", "93.184.216.35")
	cert := activeCert(t, "nyx test issuer", time.Date(2031, 3, 4, 23, 30, 0, 0, time.UTC), "a.example.org", "b.example.org")
	servers := map[string]*activeServer{}
	for _, a := range []string{"93.184.216.34", "93.184.216.35"} {
		w.seed(a)
		servers[a] = w.activeServe(a, 443, &cert, nil)
		w.closeAllBut(a, 443)
	}
	env := w.lookup("a.example.org", "b.example.org", "--active", "--fields", "tls")
	if len(env.Records) != 2 {
		t.Fatalf("records %v", env.addresses())
	}
	for i, want := range []string{"a.example.org", "b.example.org"} {
		rec := env.Records[i]
		if names := activeServerNames(activeEntries(t, rec, "tls", activeTLSKeys)); !slices.Equal(names, []string{want}) {
			t.Errorf("%s: server names %v, want %q", rec.address(), names, want)
		}
		if got := servers[rec.address()].sni(); !slices.Equal(got, []string{want}) {
			t.Errorf("%s: the server saw %v, want %q", rec.address(), got, want)
		}
	}
}

// ---- --fields ----

// --fields ports makes the TCP scan and nothing more: no handshake and no GET.
func TestIPActive_FieldsPortsMakesNoHandshakeOrGET(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.dns.A("a.example.org", addr)
	w.seed(addr)
	cert := activeCert(t, "nyx test issuer", time.Date(2031, 3, 4, 23, 30, 0, 0, time.UTC), "a.example.org")
	tlsSrv := w.activeServe(addr, 443, &cert, nil)
	httpSrv := w.activeServe(addr, 80, nil, nil)
	w.closeAllBut(addr, 80, 443)
	rec := w.record("a.example.org", "--active", "--fields", "ports")
	if want := ipExpectKeys("ports"); !slices.Equal(rec.keys, want) {
		t.Errorf("keys %v, want %v", rec.keys, want)
	}
	ports := activePorts(t, rec)
	if ports[80].str("state") != "open" || ports[443].str("state") != "open" || ports[21].str("state") != "closed" {
		t.Errorf("ports %v", rec.m["ports"])
	}
	for _, s := range []*activeServer{tlsSrv, httpSrv} {
		if s.connections() != 1 || len(s.sni()) != 0 || len(s.requests()) != 0 || s.received() != 0 {
			t.Errorf("port %d: %d connections, %d handshakes, %d requests", s.Port, s.connections(), len(s.sni()), len(s.requests()))
		}
	}
	if w.idb.count() == 0 {
		t.Error("InternetDB was not asked for the ports")
	}
}

// --fields not_contacted needs Team Cymru and nothing else: InternetDB is not asked and nothing is
// connected to, for a dedicated address and for a shared one.
func TestIPActive_FieldsNotContactedMakesNoConnection(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, addr, want string
		mods             []func(*ipFacts)
	}{
		{"dedicated", "93.184.216.34", "", nil},
		{"shared", "104.16.0.1", "shared provider infrastructure (cloudflare, cdn)", ipCloudflare},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := activeWorld(t)
			w.seed(c.addr, c.mods...)
			w.sealProbes([]string{c.addr})
			rec := w.record(c.addr, "--active", "--fields", "not_contacted")
			if want := ipExpectKeys("not_contacted"); !slices.Equal(rec.keys, want) {
				t.Errorf("keys %v, want %v", rec.keys, want)
			}
			if got := rec.str("not_contacted"); got != c.want || (c.want == "") != rec.isNull("not_contacted") {
				t.Errorf("not_contacted = %v, want %q", rec.m["not_contacted"], c.want)
			}
			if n := w.idb.count(); n != 0 {
				t.Errorf("InternetDB was asked %d times", n)
			}
			if got := w.contacted(); len(got) != 0 {
				t.Errorf("connections to %v", got)
			}
			if w.dns.Count(cymruOriginName(c.addr), "TXT") == 0 {
				t.Error("the owner was not asked of Team Cymru")
			}
		})
	}
}

// --fields geo_country under --active still works out whether the address is shared: Team Cymru is
// asked, and the keys are those of the selection.
func TestIPActive_FieldsOfOtherKeysStillAskTeamCymru(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	w := activeWorld(t)
	w.seed(addr)
	w.sealProbes([]string{addr})
	rec := w.record(addr, "--active", "--fields", "geo_country")
	if want := ipExpectKeys("geo_country"); !slices.Equal(rec.keys, want) || rec.str("geo_country") != "AU" {
		t.Errorf("record %s", rec.raw)
	}
	if w.dns.Count(cymruOriginName(addr), "TXT") == 0 {
		t.Error("the owner was not asked of Team Cymru")
	}
}
