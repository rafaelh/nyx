package cli_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Shodan tests use real stages, fake API responses and counted loopback port targets to expose
// every request/connection.

const (
	appHost = "203.0.113.7" // a dedicated address app.example.com resolves to
	rootIP  = "203.0.113.250"
)

// svc is one service Shodan reports for an address.
type svc struct {
	port      int
	transport string
	banner    string
	seen      string // a Shodan timestamp
	hostnames []string
}

func tcp(port int, banner string) svc {
	return svc{port: port, transport: "tcp", banner: banner, seen: "2026-10-30T01:02:03.456789"}
}

// hostJSON is the answer to GET /shodan/host/<ip>.
func hostJSON(ip string, hostnames []string, services ...svc) string {
	var data []map[string]any
	var ports []int
	for _, s := range services {
		data = append(data, map[string]any{"port": s.port, "transport": s.transport, "data": s.banner, "timestamp": s.seen, "hostnames": s.hostnames})
		ports = append(ports, s.port)
	}
	b, _ := json.Marshal(map[string]any{"ip_str": ip, "hostnames": hostnames, "ports": ports, "data": data})
	return string(b)
}

// matchJSON is one match of the netblock search: one service of one address.
func matchJSON(ip string, s svc) map[string]any {
	return map[string]any{"ip_str": ip, "port": s.port, "transport": s.transport, "data": s.banner, "timestamp": s.seen, "hostnames": s.hostnames}
}

func searchJSON(total int, matches ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"matches": matches, "total": total})
	return string(b)
}

// shodanFake is api.shodan.io: host lookups by address and the netblock search.
type shodanFake struct {
	mu     sync.Mutex
	hosts  map[string]string     // address -> body; an address not listed is a 404
	search func(page int) string // the answer to a net: search page
	status int                   // if set, every host lookup answers with it
}

func (f *shodanFake) setHost(ip, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts[ip] = body
}

func (f *shodanFake) setStatus(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = code
}

func (f *shodanFake) serve(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("key") != shodanKey {
		http.Error(rw, "bad key", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch path := r.URL.Path; {
	case path == "/shodan/host/search":
		page := 1
		_, _ = fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
		if f.search == nil {
			_, _ = rw.Write([]byte(searchJSON(0)))
			return
		}
		_, _ = rw.Write([]byte(f.search(page)))
	case strings.HasPrefix(path, "/shodan/host/"):
		if f.status != 0 {
			http.Error(rw, "no", f.status)
			return
		}
		body, ok := f.hosts[strings.TrimPrefix(path, "/shodan/host/")]
		if !ok {
			http.NotFound(rw, r)
			return
		}
		_, _ = rw.Write([]byte(body))
	default:
		http.NotFound(rw, r)
	}
}

// shodan installs the fake and the key.
func (p *pworld) shodan() *shodanFake {
	p.t.Helper()
	p.h.setKey("shodan", shodanKey)
	f := &shodanFake{hosts: map[string]string{}}
	p.handle("api.shodan.io", f.serve)
	return f
}

// lookups are the addresses asked of /shodan/host/<ip>, sorted.
func (p *pworld) lookups() []string {
	var out []string
	for _, r := range p.requests("api.shodan.io") {
		if rest, ok := strings.CutPrefix(r.path(), "/shodan/host/"); ok && rest != "search" {
			out = append(out, rest)
		}
	}
	slices.Sort(out)
	return out
}

// app is app.example.com on a dedicated address Shodan can be asked about.
func (p *pworld) app() {
	p.names("app.example.com")
	p.host("app.example.com", appHost)
	p.owner(appHost, 64500, "ACME-NET")
}

// portRow is the row of a ports file for the address and port, or nil.
func (p *pworld) portRow(file, ip string, port int) map[string]string {
	for _, r := range p.table(eng, file) {
		if r["ip"] == ip && r["port"] == fmt.Sprint(port) {
			return r
		}
	}
	return nil
}

func (p *pworld) openRow(ip string, port int) map[string]string {
	return p.portRow("open-ports.csv", ip, port)
}

func (p *pworld) riskPortRow(ip string, port int) map[string]string {
	return p.portRow("risk-ports.csv", ip, port)
}

// foundFindings are the finding lines of the last run: "severity value".
func (p *pworld) foundFindings() []string {
	var out []string
	for _, e := range ofType(p.h.events(), "found") {
		if strings.HasPrefix(e.str("category"), "finding ") {
			out = append(out, e.str("severity")+" "+e.str("value"))
		}
	}
	slices.Sort(out)
	return out
}

func (p *pworld) summaryNum(field string) int {
	n, _ := p.h.summaryEvent()[field].(float64)
	return int(n)
}

// passiveArgs are the arguments of a --passive run in text mode, for tests that
// read the console summary.
func (p *pworld) passiveText(args ...string) int {
	p.t.Helper()
	p.fill()
	full := append([]string{"--passive", "--no-permutations", "--rate-per-source", "1000", "--rate-dns", "100000"}, args...)
	return p.h.exec(append(full, "example.com")...)
}

// regexpLine reports whether the pattern matches somewhere in s.
func regexpLine(s, pattern string) bool { return regexp.MustCompile(pattern).MatchString(s) }

// --- The stage ---

func TestShodanHost_NotConfiguredWithoutKey(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.app()
	p.mustPassive()
	if st, reason := p.stageState("shodan-host"); st != "not-configured" || reason != "no key" {
		t.Errorf("shodan-host = %s (%s), want not-configured (no key)", st, reason)
	}
	if n := len(p.requests("api.shodan.io")); n != 0 {
		t.Errorf("%d requests to Shodan without a key", n)
	}
}

// Passive keyed Shodan lookups return dedicated-address data without target connections.
func TestShodanHost_PassiveShowsOpenAndRiskyPorts(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	f.setHost(appHost, hostJSON(appHost, nil, tcp(3389, "Remote Desktop"), tcp(8080, "HTTP/1.1 200 OK\r\nServer: nginx")))
	never := p.canary(appHost, []int{3389, 8080})

	p.mustPassive("--ports", "3389,8080")

	if got := p.lookups(); !slices.Equal(got, []string{rootIP, appHost}) {
		t.Errorf("host lookups = %v, want both dedicated addresses", got)
	}
	if st, _ := p.stageState("shodan-host"); st != "done" {
		t.Errorf("shodan-host = %s, want done", st)
	}
	if hdr, _, _ := strings.Cut(p.file(eng, "open-ports.csv"), "\n"); hdr != "ip,port,banner,hostnames,source,confirmed,shodan_last_seen,product,version,current,first_seen,last_seen" {
		t.Errorf("open-ports.csv header = %q", hdr)
	}
	rdp := p.openRow(appHost, 3389)
	if rdp == nil || rdp["source"] != "shodan" || rdp["confirmed"] != "no" || rdp["banner"] != "Remote Desktop" ||
		rdp["shodan_last_seen"] != "2026-10-30" || rdp["current"] != "true" || rdp["hostnames"] != "app.example.com" {
		t.Errorf("open-ports.csv row for 3389 = %v", rdp)
	}
	if web := p.openRow(appHost, 8080); web == nil || web["banner"] != "HTTP/1.1 200 OK" {
		t.Errorf("open-ports.csv row for 8080 = %v, want the first line of the banner", web)
	}
	// Only the risky port is a finding, one step below the confirmed severity.
	risk := p.table(eng, "risk-ports.csv")
	if len(risk) != 1 {
		t.Fatalf("risk-ports.csv = %v, want one row", risk)
	}
	if r := p.riskPortRow(appHost, 3389); r == nil || r["severity"] != "low" || r["confirmed"] != "no" || r["current"] != "true" {
		t.Errorf("risk-ports.csv row = %v, want low and unconfirmed", r)
	}
	if got := p.summaryNum("unconfirmed_risky_ports"); got != 1 {
		t.Errorf("summary unconfirmed_risky_ports = %d, want 1", got)
	}
	if n := never.conns.Load(); n != 0 {
		t.Errorf("a passive run dialled the address %d times", n)
	}
	if st, reason := p.stageState("ports"); st != "not-configured" || reason != "passive-only" {
		t.Errorf("ports = %s (%s)", st, reason)
	}
}

// A run with a key but nothing Shodan knows completes the lookups with nothing.
func TestShodanHost_UnknownAddressCompletesWithNothing(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.shodan()
	p.app()
	p.mustPassive("--ports", "3389")

	if got := p.completedKeys("shodan-host"); !slices.Equal(got, []string{rootIP, appHost}) {
		t.Errorf("completed = %v, want both addresses", got)
	}
	if st, _ := p.stageState("shodan-host"); st != "done" {
		t.Errorf("shodan-host = %s, want done", st)
	}
	if n := len(p.obsAttrs(eng, "reported_port")); n != 0 {
		t.Errorf("%d reported_port records for addresses Shodan does not know", n)
	}
	if len(p.table(eng, "open-ports.csv")) != 0 {
		t.Errorf("open-ports.csv has rows: %s", p.file(eng, "open-ports.csv"))
	}
	if f := p.h.completed(eng, "shodan-host"); len(f) != 2 {
		t.Errorf("a 404 must not leave a failed check: completed %v", f)
	}
}

// A rejected key stops the stage, like the other keyed sources.
func TestShodanHost_RejectedKeyAbortsTheStage(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	f.setStatus(401)
	// Both checks fail, and a refused key is not cured by waiting.
	if e := p.partialPassive("--ports", "3389", "--concurrency", "1"); e.transient || e.msg != "2 checks failed: shodan-host 2" {
		t.Errorf("%+v", e)
	}

	if got := p.completedKeys("shodan-host"); len(got) != 0 {
		t.Errorf("completed = %v, want nothing after a rejected key", got)
	}
	if n := len(p.lookups()); n != 1 {
		t.Errorf("%d lookups after a 401, want the stage aborted after the first", n)
	}
	if st, _ := p.stageState("shodan-host"); st != "failed" {
		t.Errorf("shodan-host = %s, want failed", st)
	}
}

// --- The cap ---

func TestShodanHost_CapDefersInAddressOrder(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.shodan()
	p.names("a.example.com", "b.example.com", "c.example.com")
	for name, ip := range map[string]string{"a.example.com": "203.0.113.30", "b.example.com": "203.0.113.20", "c.example.com": "203.0.113.10"} {
		p.host(name, ip)
		p.owner(ip, 64500, "ACME-NET")
	}
	// Four addresses with the root's; the cap takes the lowest two, in address
	// order (not text order, where .250 sorts before .30).
	p.mustPassive("--ports", "3389", "--shodan-max-hosts", "2")
	if got := p.lookups(); !slices.Equal(got, []string{"203.0.113.10", "203.0.113.20"}) {
		t.Errorf("first run looked up %v", got)
	}
	if n := deferredOf(t, p.h, "shodan-host"); n != 2 {
		t.Errorf("summary deferred shodan-host = %d, want 2", n)
	}
	if st, _ := p.stageState("shodan-host"); st != "done" {
		t.Errorf("shodan-host = %s, want done (deferred checks are not failures)", st)
	}
	if ev := lastState(p.h.events(), "shodan-host"); ev.num("failed") != 0 {
		t.Errorf("failed = %d, want 0", ev.num("failed"))
	}

	// The console summary says how many were deferred, and the next run takes the rest in order.
	if code := p.passiveText("--ports", "3389", "--shodan-max-hosts", "1"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	block := deferredBlock(t, p.h.stdout.String())
	if !strings.Contains(block, "shodan-host") || !strings.Contains(block, "1") {
		t.Errorf("the deferred block does not say one address was deferred:\n%s", block)
	}
	if got := p.lookups(); !slices.Equal(got, []string{"203.0.113.10", "203.0.113.20", "203.0.113.30"}) {
		t.Errorf("after the second run, looked up %v", got)
	}
	if code := p.passiveText("--ports", "3389", "--shodan-max-hosts", "5"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(p.h.stdout.String(), "Deferred to the next run") {
		t.Errorf("nothing is left to defer:\n%s", p.h.stdout.String())
	}
	if got := p.lookups(); len(got) != 4 {
		t.Errorf("after the third run, looked up %v, want every address once", got)
	}
}

// Shodan's data for an address is refreshed only by --redo shodan-host.
func TestShodanHost_RefreshedOnlyByRedo(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	f.setHost(appHost, hostJSON(appHost, nil, tcp(3389, "")))
	p.mustPassive("--ports", "3389,5432")
	f.setHost(appHost, hostJSON(appHost, nil, tcp(3389, ""), tcp(5432, "")))
	p.mustPassive("--ports", "3389,5432")
	if p.openRow(appHost, 5432) != nil || len(p.lookups()) != 2 {
		t.Errorf("a second run asked again: lookups %v, 5432 row %v", p.lookups(), p.openRow(appHost, 5432))
	}
	p.mustPassive("--ports", "3389,5432", "--redo", "shodan-host")
	if p.openRow(appHost, 5432) == nil {
		t.Errorf("--redo shodan-host did not refresh the address:\n%s", p.file(eng, "open-ports.csv"))
	}
}

// --- Netblocks ---

// Complete netblock searches cover returned and absent addresses without individual host
// lookups.
func TestShodanHost_CompleteNetblockSearchNeedsNoLookups(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.names("b.example.com")
	p.host("b.example.com", "198.51.100.2")
	f.search = func(int) string {
		return searchJSON(1, matchJSON("198.51.100.1", svc{port: 8080, transport: "tcp", banner: "HTTP/1.1 200 OK\r\nServer: x", seen: "2026-10-29T10:00:00"}))
	}
	p.mustPassive("--ports", "8080", "--cidr", "198.51.100.0/30")

	if got := p.lookups(); !slices.Equal(got, []string{rootIP}) {
		t.Errorf("host lookups = %v, want only the address outside the netblock", got)
	}
	r := p.openRow("198.51.100.1", 8080)
	if r == nil || r["source"] != "shodan" || r["banner"] != "HTTP/1.1 200 OK" || r["shodan_last_seen"] != "2026-10-29" {
		t.Errorf("the search's port = %v", r)
	}
	if attrs := p.obsAttrs(eng, "shodan_netblock"); !strings.Contains(attrs["198.51.100.0/30"], `"truncated":false`) {
		t.Errorf("shodan_netblock = %v", attrs)
	}
	if notes, _ := p.h.summaryEvent()["notes"].([]any); len(notes) != 0 {
		t.Errorf("notes = %v, want none for a complete search", notes)
	}
}

// Capped searches allow eligible missed addresses to be looked up individually and report the
// truncation.
func TestShodanHost_TruncatedSearchLooksUpWhatItMissed(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.names("m.example.com")
	p.host("m.example.com", "198.51.100.12")
	f.search = func(page int) string {
		return searchJSON(1000, matchJSON(fmt.Sprintf("198.51.100.%d", page), tcp(8080, "")))
	}
	p.mustPassive("--ports", "8080", "--cidr", "198.51.100.0/28")

	if got := p.lookups(); !slices.Equal(got, []string{"198.51.100.12", rootIP}) {
		t.Errorf("host lookups = %v, want the address the search missed and the one outside", got)
	}
	if attrs := p.obsAttrs(eng, "shodan_netblock"); !strings.Contains(attrs["198.51.100.0/28"], `"truncated":true`) {
		t.Errorf("shodan_netblock = %v", attrs)
	}
	notes, _ := p.h.summaryEvent()["notes"].([]any)
	if len(notes) != 1 || !strings.Contains(fmt.Sprint(notes[0]), "198.51.100.0/28") || !strings.Contains(fmt.Sprint(notes[0]), "truncated") {
		t.Errorf("notes = %v, want one naming the truncated search", notes)
	}
	// The console summary carries it too.
	if code := p.passiveText("--ports", "8080", "--cidr", "198.51.100.0/28"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out := p.h.stdout.String(); !strings.Contains(out, "198.51.100.0/28") || !strings.Contains(out, "truncated") {
		t.Errorf("the console summary does not mention the truncated search:\n%s", out)
	}
}

// Any returned address counts as covered, including UDP-only matches that create no port
// report.
func TestShodanHost_TruncatedSearchReturnedUDPOnly(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.names("m.example.com")
	p.host("m.example.com", "198.51.100.12")
	f.search = func(page int) string {
		return searchJSON(1000, matchJSON(fmt.Sprintf("198.51.100.%d", page), svc{port: 161, transport: "udp", seen: "2026-10-30T00:00:00"}))
	}
	p.mustPassive("--ports", "8080", "--cidr", "198.51.100.0/28")

	if got := p.lookups(); !slices.Equal(got, []string{"198.51.100.12", rootIP}) {
		t.Errorf("host lookups = %v, want only the address the search missed and the one outside", got)
	}
	if n := len(p.obsAttrs(eng, "reported_port")); n != 0 {
		t.Errorf("%d reported_port records from UDP matches", n)
	}
}

// --- Shodan never widens what nyx connects to ---

func TestShodanHost_ReportedPortsAreNeverDialledOrProbed(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	p.serve(appHost, 7001, hello)
	// 8080 speaks HTTP and 3306 is risky, but neither is on the port list.
	f.setHost(appHost, hostJSON(appHost, nil, tcp(8080, "HTTP/1.1 200 OK"), tcp(3306, "mysql")))
	never := p.canary(appHost, []int{8080, 3306})

	p.sweep([]int{7001})

	if n := never.conns.Load(); n != 0 {
		t.Errorf("a port only Shodan reported was dialled %d times", n)
	}
	for _, k := range p.completedKeys("ports") {
		if strings.Contains(k, ":8080") || strings.Contains(k, ":3306") {
			t.Errorf("a port check was made for a Shodan port: %s", k)
		}
	}
	for _, k := range p.completedKeys("httpprobe") {
		if strings.Contains(k, ":8080") {
			t.Errorf("the probe checked a Shodan-only port: %s", k)
		}
	}
	// Both are shown, unconfirmed.
	for _, port := range []int{8080, 3306} {
		if r := p.openRow(appHost, port); r == nil || r["confirmed"] != "no" || r["source"] != "shodan" || r["current"] != "true" {
			t.Errorf("open-ports.csv row for %d = %v, want shown unconfirmed", port, r)
		}
	}
	if r := p.riskPortRow(appHost, 3306); r == nil || r["severity"] != "low" || r["confirmed"] != "no" {
		t.Errorf("risk-ports.csv row for 3306 = %v", r)
	}
	if got := p.table(eng, "web-services.csv"); find(got, "port", "8080") != nil {
		t.Errorf("a web service was probed on a Shodan-only port: %v", got)
	}
}

// --- Passive, then active ---

// nyx's own handshake decides: open confirms and raises the finding, a
// rejection takes the row out, and silence leaves it as Shodan said.
func TestShodanHost_ActiveRunSettlesWhatShodanReported(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	f.setHost(appHost, hostJSON(appHost, nil, tcp(3389, "shodan says rdp"), tcp(3306, "shodan says mysql"), tcp(5432, "shodan says pg")))
	open := p.serve(appHost, 3389, hello) // 3306 is refused and 5432 does not answer
	p.filter(appHost, 5432)
	ports := []int{3389, 3306, 5432}

	// Passive: all three are unconfirmed findings, and nothing is dialled.
	p.mustPassive("--ports", "3389,3306,5432")
	if got := p.foundFindings(); !slices.Equal(got, []string{"low " + appHost + ":3306", "low " + appHost + ":3389", "low " + appHost + ":5432"}) {
		t.Errorf("passive found lines = %v", got)
	}
	if got := p.summaryNum("unconfirmed_risky_ports"); got != 3 {
		t.Errorf("unconfirmed_risky_ports = %d, want 3", got)
	}
	if n := open.conns.Load(); n != 0 {
		t.Fatalf("the passive run dialled %d times", n)
	}

	// Active: one handshake per port.
	p.sweep(ports)
	if n := open.conns.Load(); n != 1 {
		t.Errorf("handshakes to the open port = %d, want 1", n)
	}
	if got, want := p.checked(), portKeys([]string{appHost, rootIP}, ports); !slices.Equal(got, want) {
		t.Errorf("port checks = %v\nwant       %v: one per address and port, and no extra for a reported one", got, want)
	}

	// Open: confirmed, nyx's banner, full severity, and a new + line at it.
	rdp := p.openRow(appHost, 3389)
	if rdp == nil || rdp["source"] != "nyx;shodan" || rdp["confirmed"] != "yes" || rdp["banner"] != strings.TrimSpace(hello)+`\r\n` ||
		rdp["shodan_last_seen"] != "2026-10-30" || rdp["current"] != "true" {
		t.Errorf("open row = %v", rdp)
	}
	if r := p.riskPortRow(appHost, 3389); r == nil || r["severity"] != "medium" || r["confirmed"] != "yes" || r["current"] != "true" {
		t.Errorf("risk row for the open port = %v", r)
	}
	if got := p.foundFindings(); !slices.Equal(got, []string{"medium " + appHost + ":3389"}) {
		t.Errorf("found lines = %v, want one new line at the raised severity", got)
	}
	// Rejected: the row is no longer current, and so is its finding.
	if r := p.openRow(appHost, 3306); r == nil || r["current"] != "false" {
		t.Errorf("rejected port's row = %v, want not current", r)
	}
	if r := p.riskPortRow(appHost, 3306); r != nil && r["current"] == "true" {
		t.Errorf("rejected port still a current finding: %v", r)
	}
	// Silent: still shown, unconfirmed, still the low finding.
	if r := p.openRow(appHost, 5432); r == nil || r["current"] != "true" || r["confirmed"] != "no" || r["source"] != "shodan" {
		t.Errorf("silent port's row = %v", r)
	}
	if r := p.riskPortRow(appHost, 5432); r == nil || r["severity"] != "low" || r["confirmed"] != "no" || r["current"] != "true" {
		t.Errorf("silent port's finding = %v", r)
	}
	checks := p.obsAttrs(eng, "port_check")
	if !strings.Contains(checks[appHost+":3306"], `"closed"`) || !strings.Contains(checks[appHost+":5432"], `"silent"`) || checks[appHost+":3389"] != "" {
		t.Errorf("port_check records = %v", checks)
	}
	// The summary splits the counts.
	if c, r := p.h.total("open ports (confirmed)"), p.h.total("open ports (third-party reported)"); c != 1 || r != 1 {
		t.Errorf("open ports confirmed %d, reported %d; want 1 and 1 (the rejected one is in neither)", c, r)
	}
	if got := p.summaryNum("unconfirmed_risky_ports"); got != 1 {
		t.Errorf("unconfirmed_risky_ports = %d, want 1", got)
	}

	// Nothing changed: no new lines and no more handshakes.
	p.sweep(ports)
	if got := p.foundFindings(); len(got) != 0 {
		t.Errorf("a repeat run printed %v", got)
	}
	if n := open.conns.Load(); n != 1 {
		t.Errorf("handshakes to the open port = %d after a third run, want 1", n)
	}
}

// A closed port only Shodan reports is in neither count and is no current
// finding, even though it was reported before nyx looked.
func TestShodanHost_ClosedPortIsInNoCountOrFinding(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	f.setHost(appHost, hostJSON(appHost, nil, tcp(3306, "mysql")))

	p.sweep([]int{3306})

	if r := p.openRow(appHost, 3306); r == nil || r["current"] != "false" {
		t.Errorf("open-ports.csv row = %v, want listed and not current", r)
	}
	for _, c := range []string{"open ports (confirmed)", "open ports (third-party reported)"} {
		if n := p.h.total(c); n != 0 {
			t.Errorf("%s = %d, want 0", c, n)
		}
	}
	if n := p.summaryNum("unconfirmed_risky_ports"); n != 0 {
		t.Errorf("unconfirmed_risky_ports = %d, want 0", n)
	}
	if r := p.riskPortRow(appHost, 3306); r != nil && r["current"] == "true" {
		t.Errorf("risk-ports.csv has a current row for a closed port: %v", r)
	}
	// The report came with the first check: no second handshake was made for it.
	if got, want := p.checked(), portKeys([]string{appHost, rootIP}, []int{3306}); !slices.Equal(got, want) {
		t.Errorf("port checks = %v, want %v", got, want)
	}
}

// --- Active, then Shodan ---

// A later report allows one extra check for an unconfirmed port, never repeated checks for
// already-open ports.
func TestShodanHost_LateReportCostsOneExtraHandshake(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.app()
	open := p.serve(appHost, 3389, hello)
	ports := []int{3389, 3306}
	p.sweep(ports) // no key: nothing is reported
	if got, want := p.checked(), portKeys([]string{appHost, rootIP}, ports); !slices.Equal(got, want) {
		t.Fatalf("first checks = %v", got)
	}

	f := p.shodan()
	f.setHost(appHost, hostJSON(appHost, nil, tcp(3389, ""), tcp(3306, "")))
	p.sweep(ports)
	extra := func() []string {
		var out []string
		for _, k := range p.checked() {
			if strings.HasSuffix(k, "|reported") {
				out = append(out, k)
			}
		}
		return out
	}
	if got := extra(); !slices.Equal(got, []string{appHost + ":3306|reported"}) {
		t.Errorf("extra checks = %v, want one, for the reported port with no open record", got)
	}
	if n := open.conns.Load(); n != 1 {
		t.Errorf("the open port was handshaken %d times, want 1", n)
	}
	if r := p.openRow(appHost, 3306); r == nil || r["current"] != "false" {
		t.Errorf("the rejected port's row = %v", r)
	}

	p.sweep(ports)
	if got := extra(); len(got) != 1 {
		t.Errorf("a later run checked again: %v", got)
	}
	if n := open.conns.Load(); n != 1 {
		t.Errorf("the open port was handshaken %d times, want 1", n)
	}
}

// --- What is recorded ---

func TestShodanHost_BannersUDPAndHostnames(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	long := strings.Repeat("x", 300)
	f.setHost(appHost, hostJSON(appHost, []string{"app.example.com", "www.other.org", "*.example.com"},
		tcp(22, long),
		tcp(23, "login:\x1b[31mred\x07"),
		tcp(8080, "HTTP/1.1 200 OK\r\nServer: nginx"),
		svc{port: 161, transport: "udp", banner: "snmp", seen: "2026-10-30T00:00:00"},
		svc{port: 53, transport: "udp", seen: "2026-10-30T00:00:00", hostnames: []string{"dns.other.net"}}))
	p.mustPassive("--ports", "22,23,8080")

	if r := p.openRow(appHost, 22); r == nil || r["banner"] != long[:256] {
		t.Errorf("a long banner = %q, want its first 256 characters", r["banner"])
	}
	if r := p.openRow(appHost, 8080); r == nil || r["banner"] != "HTTP/1.1 200 OK" {
		t.Errorf("a multi-line banner = %q, want its first line", r["banner"])
	}
	r := p.openRow(appHost, 23)
	if r == nil || strings.ContainsAny(r["banner"], "\x1b\x07") || !strings.Contains(r["banner"], `\x1b`) {
		t.Errorf("a banner with control characters = %q, want it escaped like nyx's own", r["banner"])
	}
	if strings.ContainsRune(p.file(eng, "open-ports.csv"), '\x1b') {
		t.Error("open-ports.csv holds an escape character")
	}
	for _, port := range []int{161, 53} {
		if p.openRow(appHost, port) != nil {
			t.Errorf("UDP port %d was recorded", port)
		}
	}
	if !slices.Contains(p.lines(eng, "subdomains.txt"), "app.example.com") {
		t.Errorf("subdomains.txt = %v", p.lines(eng, "subdomains.txt"))
	}
	// A hostname outside every root is a candidate root, and never a hostname.
	cand := p.table(eng, "candidates.csv")
	if c := find(cand, "value", "other.org"); c == nil || c["type"] != "root" {
		t.Errorf("candidates.csv = %v, want other.org as a root", cand)
	}
	for _, c := range cand {
		if strings.Contains(c["value"], "www.other.org") || c["value"] == "dns.other.net" || c["value"] == "other.net" {
			t.Errorf("an unexpected candidate %v (a UDP service's hostnames are not recorded either)", c)
		}
	}
	if _, ok := p.obsAttrs(eng, "hostname")["www.other.org"]; ok {
		t.Error("an out-of-scope name was recorded as a hostname")
	}
	ips := p.table(eng, "ips.csv")
	if row := find(ips, "ip", appHost); row == nil || !strings.Contains(row["hostnames"], "app.example.com") {
		t.Errorf("ips.csv row = %v", row)
	}
}

func TestShodanHost_ConsoleSummarySplitsOpenPorts(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	f.setHost(appHost, hostJSON(appHost, nil, tcp(3389, ""), tcp(8080, "")))
	if code := p.passiveText("--ports", "3389,8080"); code != 0 {
		t.Fatalf("exit %d\n%s", code, p.h.stderr.String())
	}
	out := p.h.stdout.String()
	for _, want := range []string{"open ports (confirmed)", "open ports (third-party reported)", "1 risky ports reported by Shodan, unconfirmed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the console summary lacks %q:\n%s", want, out)
		}
	}
	if !regexpLine(out, `open ports \(confirmed\)\s+0`) || !regexpLine(out, `open ports \(third-party reported\)\s+2`) {
		t.Errorf("the open-port counts are wrong:\n%s", out)
	}
	// With none, there is no line.
	q := newPorts(t)
	q.shodan()
	q.app()
	if code := q.passiveText("--ports", "3389"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(q.h.stdout.String(), "risky ports reported by Shodan") {
		t.Errorf("a summary with no unconfirmed risky ports has the line:\n%s", q.h.stdout.String())
	}
}

// --- Candidates ---

// shodan and shodan-host are both passive DNS: a root they alone report has one
// family and is low, whichever sees it.
func TestShodanHost_CandidateRootFromBothIsOneFamily(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	f.search = func(int) string {
		return searchJSON(1, matchJSON("198.51.100.1", svc{port: 8080, transport: "tcp", seen: "2026-10-29T10:00:00", hostnames: []string{"x.other.org"}}))
	}
	f.setHost(rootIP, hostJSON(rootIP, []string{"y.other.org"}, tcp(8080, "")))
	p.mustPassive("--ports", "8080", "--cidr", "198.51.100.0/30")

	c := find(p.table(eng, "candidates.csv"), "value", "other.org")
	if c == nil {
		t.Fatalf("other.org is not a candidate: %s", p.file(eng, "candidates.csv"))
	}
	if c["type"] != "root" || c["sources"] != "shodan;shodan-host" || c["confidence"] != "low" {
		t.Errorf("other.org = %v, want a root from both stages with low confidence", c)
	}
}

// --- The documentation ---

func TestShodanHost_DocsSayWhatItDoes(t *testing.T) {
	t.Parallel()
	docs := docsText(t)
	for _, want := range []string{
		"shodan-host", "--redo shodan-host", "--redo shodan", "shodan.max_hosts", "--shodan-max-hosts",
		"shodan_last_seen", "third-party reported", "unconfirmed", "per dedicated in-scope address", "rate-limited",
	} {
		if !strings.Contains(docs, want) {
			t.Errorf("the docs do not mention %q", want)
		}
	}
}
