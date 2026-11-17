package cli_test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Historical DNS and origin exposure. The tests drive cli.Execute with the real dnshistory and
// origincheck stages. A SecurityTrails fake answers history lookups; every address a candidate
// origin could have is mapped to a loopback server (or a closed port), so nothing leaves the machine.
//
// The standard world: www.example.com is a CNAME to Fastly and answers 200 "Acme Corp" from the CDN
// at 203.0.113.10. origin.example.com is a sibling at 203.0.113.20 (owner known, dedicated), whose
// certificate names www.example.com and whose page is titled "Origin Server" for its own name; for
// the Host www.example.com it serves the Acme Corp page, so it is the exposed origin.

const (
	cdnAddr      = "203.0.113.10"
	siblingAddr  = "203.0.113.20"
	histInNet    = "198.51.100.50" // inside --cidr 198.51.100.0/24: may be contacted
	histOutside  = "203.0.113.90"  // owner known and dedicated, but not in a netblock and no host's address
	acmeTitle    = "Acme Corp"
	originWWW    = "www.example.com"
	originBadRaw = "<title>Different</title>tiny"
)

// siteBody is a page of a little over a kilobyte, so that a title of another length stays within 10%.
func siteBody(title string) string {
	return "<html><head><title>" + title + "</title></head><body>" + strings.Repeat("Acme ", 200) + "</body></html>"
}

type histRec struct{ addr, first, last string }

// stHistory is api.securitytrails.com's DNS history: /v1/history/<host>/dns/a and /aaaa. The key is
// checked and every other path is a 404.
type stHistory struct {
	mu      sync.Mutex
	records map[string][]histRec // "host/a" or "host/aaaa"
	asked   []string             // "host/type", in order
}

func (f *stHistory) set(host, typ string, recs ...histRec) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[host+"/"+typ] = recs
}

func (f *stHistory) serve(rw http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "v1" || parts[1] != "history" || parts[3] != "dns" {
		http.NotFound(rw, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("APIKEY") != securityTrailsKey {
		http.Error(rw, "bad key", http.StatusForbidden)
		return
	}
	key := parts[2] + "/" + parts[4]
	f.asked = append(f.asked, key)
	var records []map[string]any
	for _, rec := range f.records[key] {
		field := "ip"
		if parts[4] == "aaaa" {
			field = "ipv6"
		}
		records = append(records, map[string]any{"first_seen": rec.first, "last_seen": rec.last, "type": parts[4],
			"organizations": []string{"ACME-NET"}, "values": []map[string]any{{field: rec.addr}}})
	}
	_ = json.NewEncoder(rw).Encode(map[string]any{"records": records, "pages": 1, "type": parts[4]})
}

// askedHosts are the distinct hosts asked of, in order.
func (f *stHistory) askedHosts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, k := range f.asked {
		if h, _, _ := strings.Cut(k, "/"); !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

func (f *stHistory) askedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

type originOpts struct {
	noKey       bool
	byRange     bool // www is fronted by a Cloudflare published range, not by a CNAME
	siblingCert bool // the sibling's certificate names www
	noSibling   bool
}

// oworld is the standard world. cdnTitle and the origin's answer change between runs.
type oworld struct {
	*web
	hist    *stHistory
	cdn     *site
	sibling *site

	mu         sync.Mutex
	cdnTitle   string
	cdnStatus  int
	originRaw  string // when set, the answer to Host www.example.com
	originWWW  string // the title of that answer otherwise
	ownTitle   string // the title of the sibling's page for its own name
	siblingCrt tls.Certificate
	cfRanges   string
	provider   string // the provider fronting www.example.com
}

func newOriginWorld(t *testing.T, mod ...func(*originOpts)) *oworld {
	t.Helper()
	o := originOpts{siblingCert: true}
	for _, m := range mod {
		m(&o)
	}
	x := &oworld{web: newWeb(t), hist: &stHistory{records: map[string][]histRec{}},
		cdnTitle: acmeTitle, cdnStatus: 200, originWWW: acmeTitle, ownTitle: "Origin Server", provider: "fastly"}
	if !o.noKey {
		t.Setenv("NYX_KEYS_SECURITYTRAILS", securityTrailsKey)
	}
	x.handle("api.securitytrails.com", x.hist.serve)
	x.names("www.example.com", "origin.example.com")
	if o.byRange {
		x.cfRanges, x.provider = "104.16.0.0/13\n203.0.113.8/29\n", "cloudflare"
		serveNewRanges(x.world)
		x.handle("www.cloudflare.com", func(rw http.ResponseWriter, r *http.Request) {
			x.mu.Lock()
			defer x.mu.Unlock()
			if r.URL.Path == "/ips-v4" {
				_, _ = rw.Write([]byte(x.cfRanges))
				return
			}
			http.NotFound(rw, r)
		})
		x.host("www.example.com", cdnAddr)
	} else {
		x.dns.CNAME("www.example.com", "x.global.fastly.net")
		x.host("x.global.fastly.net", cdnAddr)
	}
	x.cdn = x.secure(cdnAddr, 443, selfFor(t, "www.example.com"), func(w http.ResponseWriter, r *http.Request) {
		x.mu.Lock()
		title, status := x.cdnTitle, x.cdnStatus
		x.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(siteBody(title)))
	})
	if !o.noSibling {
		x.host("origin.example.com", siblingAddr)
		x.owner(siblingAddr, 64500, "ACME-NET")
		names := []string{"origin.example.com"}
		if o.siblingCert {
			names = append(names, "www.example.com")
		}
		x.siblingCrt = selfSigned(t, leafSpec{cn: "origin.example.com", dns: names})
		x.sibling = x.secureConfig(siblingAddr, 443, func() *tls.Config {
			x.mu.Lock()
			defer x.mu.Unlock()
			return &tls.Config{Certificates: []tls.Certificate{x.siblingCrt}}
		}, x.originHandler)
	}
	x.owner(histOutside, 64500, "ACME-NET")
	return x
}

// originHandler is the origin server: for Host www.example.com it serves the site, otherwise its own page.
func (x *oworld) originHandler(w http.ResponseWriter, r *http.Request) {
	x.mu.Lock()
	raw, title, own := x.originRaw, x.originWWW, x.ownTitle
	x.mu.Unlock()
	w.Header().Set("Content-Type", "text/html")
	switch {
	case strings.HasPrefix(r.Host, originWWW) && raw != "":
		_, _ = w.Write([]byte(raw))
	case strings.HasPrefix(r.Host, originWWW):
		_, _ = w.Write([]byte(siteBody(title)))
	default:
		_, _ = w.Write([]byte(siteBody(own)))
	}
}

func (x *oworld) set(f func()) { x.mu.Lock(); f(); x.mu.Unlock() }

// run is web.run with the in-scope netblock, so the historical addresses in it may be contacted.
func (x *oworld) run(args ...string) int {
	x.t.Helper()
	return x.web.run(append([]string{"--cidr", "198.51.100.0/24"}, args...)...)
}

func (x *oworld) mustRun(args ...string) {
	x.t.Helper()
	if code := x.run(args...); code != 0 {
		x.t.Fatalf("exit %d\n%s", code, x.h.stdout.String())
	}
}

func (x *oworld) rows() []map[string]string { return x.table(eng, "risk-origin-exposure.csv") }

// row is the origin-exposure row of an address for www.example.com.
func (x *oworld) row(addr string) map[string]string {
	x.t.Helper()
	for _, r := range x.rows() {
		if r["hostname"] == originWWW && r["address"] == addr {
			return r
		}
	}
	return nil
}

func (x *oworld) wantRow(addr, severity, foundBy, confirmedBy, confirmed, current string) {
	x.t.Helper()
	r := x.row(addr)
	if r == nil {
		x.t.Fatalf("risk-origin-exposure.csv has no row for %s:\n%s", addr, x.file(eng, "risk-origin-exposure.csv"))
	}
	want := map[string]string{"severity": severity, "provider": x.provider, "found_by": foundBy, "confirmed_by": confirmedBy, "confirmed": confirmed, "current": current}
	for k, v := range want {
		if r[k] != v {
			x.t.Errorf("%s: %s = %q, want %q (row %v)", addr, k, r[k], v, r)
		}
	}
}

// wwwGets counts the requests that reached a server for Host www.example.com, which only an
// origin check sends there (the probe asks a server for its own name).
func wwwGets(s *site, scheme string) int {
	n := 0
	for _, r := range s.requests() {
		if strings.HasPrefix(r.Host, originWWW) && r.URI == "/" && r.Method == "GET" && r.TLS == (scheme == "https") {
			n++
		}
	}
	return n
}

// historicalOrigin serves the exposed origin at an address in the netblock.
func (x *oworld) historicalOrigin() *site {
	return x.secure(histInNet, 443, selfFor(x.t, originWWW), x.originHandler)
}

// --- the standard cases ---

// A historical address is a row in resolutions.csv and ips.csv, is contacted once it is in a netblock,
// and when it answers with the fronted host's own title it is a confirmed medium finding with a
// `+` line, the row's provider, how it was found and what confirmed it.
func TestOrigin_HistoricalOriginConfirmedByTitle(t *testing.T) {
	x := newOriginWorld(t, func(o *originOpts) { o.noSibling = true })
	x.hist.set(originWWW, "a", histRec{histInNet, "2023-01-01", "2024-02-02"})
	x.hist.set(originWWW, "aaaa", histRec{"2001:db8::5", "2022-03-03", "2022-04-04"})
	origin := x.historicalOrigin()
	x.mustRun()

	x.wantRow(histInNet, "medium", "historical", "title", "yes", "true")
	if got := wwwGets(origin, "https"); got != 1 {
		t.Errorf("the origin got %d GETs for the fronted host over https, want 1", got)
	}
	if got := origin.requests()[0]; got.Method != "GET" || got.URI != "/" || got.Host != originWWW || !got.TLS {
		t.Errorf("request = %+v", got)
	}
	if sni := origin.sniSeen(); len(sni) == 0 || sni[0] != originWWW {
		t.Errorf("server name = %v, want www.example.com", sni)
	}

	res := x.table(eng, "resolutions.csv")
	var hist []string
	for _, r := range res {
		if strings.HasSuffix(r["type"], "-historical") {
			hist = append(hist, fmt.Sprintf("%s|%s|%s|%s|%s|%s", r["name"], r["type"], r["value"], r["source"], r["historical_first_seen"], r["historical_last_seen"]))
		} else if r["historical_first_seen"] != "" || r["historical_last_seen"] != "" {
			t.Errorf("a current row has historical dates: %v", r)
		}
	}
	slices.Sort(hist)
	want := []string{"www.example.com|A-historical|198.51.100.50|dnshistory|2023-01-01|2024-02-02",
		"www.example.com|AAAA-historical|2001:db8::5|dnshistory|2022-03-03|2022-04-04"}
	if !slices.Equal(hist, want) {
		t.Errorf("historical rows = %v, want %v", hist, want)
	}
	if hdr := strings.SplitN(x.file(eng, "resolutions.csv"), "\n", 2)[0]; hdr != "name,type,value,source,self_hosted,historical_first_seen,historical_last_seen,current,first_seen,last_seen" {
		t.Errorf("resolutions.csv header = %q", hdr)
	}
	if r := find(x.table(eng, "ips.csv"), "ip", histInNet); r == nil || r["hostnames"] != "" {
		t.Errorf("a historical address is in ips.csv without a hostname: %v", r)
	}

	// The found line and the summary carry the finding.
	var line event
	for _, e := range ofType(x.h.events(), "found") {
		if strings.HasPrefix(e.str("category"), "finding origin-exposure") {
			line = e
		}
	}
	if line == nil || line.str("severity") != "medium" || line.str("text") != "origin exposure www.example.com -> 198.51.100.50 (behind fastly)" {
		t.Errorf("found event = %v", line)
	}
	listed := false
	for _, f := range ofType(x.h.events(), "summary")[0]["findings"].([]any) {
		if m := f.(map[string]any); m["category"] == "origin-exposure" && m["severity"] == "medium" {
			listed = true
		}
	}
	if !listed {
		t.Error("the summary does not list the confirmed origin exposure")
	}
}

// The console line.
func TestOrigin_ConsoleLine(t *testing.T) {
	x := newOriginWorld(t, func(o *originOpts) { o.noSibling = true })
	x.hist.set(originWWW, "a", histRec{histInNet, "2023-01-01", "2024-02-02"})
	x.historicalOrigin()
	x.fill()
	code := x.h.exec("--authorised", "--rate-per-host", "1000", "--rate-per-source", "1000", "--rate-dns", "100000",
		"--no-permutations", "--cidr", "198.51.100.0/24", "example.com")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	re := regexp.MustCompile(`^\+ medium\s+origin exposure www\.example\.com -> 198\.51\.100\.50 \(behind fastly\)$`)
	if !slices.ContainsFunc(x.h.logMsgs("INFO"), re.MatchString) {
		t.Errorf("no + line matches %v in:\n%s", re, x.h.stderr.String())
	}
}

// The probe records the length of the first response's body, which the body-size rule compares.
func TestOrigin_ProbeRecordsBodyLength(t *testing.T) {
	x := newOriginWorld(t, func(o *originOpts) { o.noSibling = true })
	x.mustRun()
	attrs := x.obsAttrs(eng, "web_service")["https://www.example.com"]
	if want := fmt.Sprintf(`"body_len":%d`, len(siteBody(acmeTitle))); !strings.Contains(attrs, want) {
		t.Errorf("web_service attrs = %s, want %s", attrs, want)
	}
}

// A sibling is found by its certificate, by its title, or both; the exposure is confirmed by the
// title the origin answers with, or by the same status, a similar body and a certificate that names
// the host. A certificate that names the host is not enough by itself.
func TestOrigin_SiblingFoundByCertificateAndByTitle(t *testing.T) {
	t.Run("by certificate, confirmed by status, size and certificate", func(t *testing.T) {
		x := newOriginWorld(t)
		x.set(func() { x.originWWW = "" }) // no title: only the body rule can confirm
		x.mustRun()
		x.wantRow(siblingAddr, "medium", "sibling-certificate", "status-body-certificate", "yes", "true")
		if got := wwwGets(x.sibling, "https"); got != 1 {
			t.Errorf("origin checks = %d, want 1", got)
		}
	})
	t.Run("by certificate and title", func(t *testing.T) {
		x := newOriginWorld(t)
		x.set(func() { x.ownTitle = acmeTitle })
		x.mustRun()
		x.wantRow(siblingAddr, "medium", "sibling-certificate;sibling-title", "title", "yes", "true")
	})
	t.Run("by title alone", func(t *testing.T) {
		x := newOriginWorld(t, func(o *originOpts) { o.siblingCert = false })
		x.set(func() { x.ownTitle = acmeTitle })
		x.mustRun()
		x.wantRow(siblingAddr, "medium", "sibling-title", "title", "yes", "true")
	})
	t.Run("a certificate alone leaves a possible origin", func(t *testing.T) {
		x := newOriginWorld(t)
		x.set(func() { x.originRaw = originBadRaw })
		x.mustRun()
		x.wantRow(siblingAddr, "low", "sibling-certificate", "", "no", "true")
		if got := wwwGets(x.sibling, "https"); got != 1 {
			t.Errorf("the sibling was still checked once, got %d", got)
		}
	})
	t.Run("neither a certificate nor a title is no candidate and no request", func(t *testing.T) {
		x := newOriginWorld(t, func(o *originOpts) { o.siblingCert = false })
		x.mustRun()
		if r := x.rows(); len(r) != 0 {
			t.Errorf("rows = %v", r)
		}
		if got := wwwGets(x.sibling, "https"); got != 0 {
			t.Errorf("an unrelated host was sent %d requests for www", got)
		}
	})
}

// --- candidates that may not be contacted ---

// An address that may not be contacted is reported as a possible origin, and nothing is sent to it:
// not the check, not a probe, not a port check. A historical address is an address in ips.csv and
// no more, whatever it is a historical address of.
func TestOrigin_UncontactableCandidateIsPossibleAndNeverContacted(t *testing.T) {
	x := newOriginWorld(t, func(o *originOpts) { o.noSibling = true })
	x.hist.set(originWWW, "a", histRec{histOutside, "2023-01-01", "2024-02-02"})
	canary443 := x.secure(histOutside, 443, selfFor(t, originWWW), x.originHandler)
	canary80 := x.plain(histOutside, 80, x.originHandler)
	x.mustRun("--ports", "443")

	x.wantRow(histOutside, "low", "historical", "", "no", "true")
	if canary443.hits() != 0 || canary80.hits() != 0 || canary443.hellos.Load() != 0 {
		t.Errorf("an uncontactable address was contacted: 443 %d requests, 80 %d requests", canary443.hits(), canary80.hits())
	}
	r := find(x.table(eng, "ips.csv"), "ip", histOutside)
	if r == nil || r["port_eligible"] != "false" || r["hostnames"] != "" {
		t.Errorf("ips.csv row = %v", r)
	}
	if len(x.requests("api.shodan.io")) != 0 {
		t.Error("nothing asked Shodan")
	}
	if got := x.completedKeys("origincheck"); len(got) != 0 {
		t.Errorf("origincheck checks = %v, want none", got)
	}
	// The stage yields no check for it: egress would refuse one, but that would be a failed check.
	if ev := lastState(x.h.events(), "origincheck"); ev.num("checks") != 0 || ev.num("failed") != 0 {
		t.Errorf("origincheck state = %v, want no checks and none failed", ev)
	}
}

// An excluded address is never contacted either, even inside an in-scope netblock.
func TestOrigin_ExcludedCandidateIsNeverContacted(t *testing.T) {
	x := newOriginWorld(t, func(o *originOpts) { o.noSibling = true })
	x.hist.set(originWWW, "a", histRec{histInNet, "2023-01-01", "2024-02-02"})
	canary := x.historicalOrigin()
	x.mustRun("--exclude", histInNet)
	if canary.hits() != 0 {
		t.Errorf("an excluded address was contacted %d times", canary.hits())
	}
	x.wantRow(histInNet, "low", "historical", "", "no", "true")
}

// No check is created until the probe has a 2xx result for the fronted host; once it does, the
// pair is checked.
func TestOrigin_NoCheckBeforeTheProbeHasA2xx(t *testing.T) {
	x := newOriginWorld(t)
	x.set(func() { x.cdnStatus = 403 }) // the CDN blocks the probe
	x.mustRun()
	x.wantRow(siblingAddr, "low", "sibling-certificate", "", "no", "true")
	if got := wwwGets(x.sibling, "https"); got != 0 {
		t.Errorf("origin checks before a 2xx = %d, want 0", got)
	}
	x.set(func() { x.cdnStatus = 200 })
	x.mustRun("--redo", "httpprobe")
	x.wantRow(siblingAddr, "medium", "sibling-certificate", "title", "yes", "true")
	if got := wwwGets(x.sibling, "https"); got != 1 {
		t.Errorf("origin checks after a 2xx = %d, want 1", got)
	}
}

// If the title the probe saw changes, the pair is checked again, and what the new check finds is
// what counts: the origin no longer carries the new title, so it is confirmed by size instead.
func TestOrigin_ChangedTitleChecksAgain(t *testing.T) {
	x := newOriginWorld(t)
	x.mustRun()
	x.wantRow(siblingAddr, "medium", "sibling-certificate", "title", "yes", "true")
	if got := wwwGets(x.sibling, "https"); got != 1 {
		t.Fatalf("first run: %d checks", got)
	}
	x.mustRun() // nothing changed: nothing is sent again
	if got := wwwGets(x.sibling, "https"); got != 1 {
		t.Errorf("an unchanged pair was checked again: %d", got)
	}
	x.set(func() { x.cdnTitle = "Acme Corp (new)" })
	x.mustRun("--redo", "httpprobe")
	if got := wwwGets(x.sibling, "https"); got != 2 {
		t.Errorf("a changed title was not checked again: %d checks", got)
	}
	x.wantRow(siblingAddr, "medium", "sibling-certificate", "status-body-certificate", "yes", "true")
}

// The check is one GET per scheme. It falls back to HTTP on 80 only when nothing answers on 443,
// not when 443 answers or fails the TLS handshake.
func TestOrigin_HTTPFallbackOnlyWhenNothingAnswersOn443(t *testing.T) {
	setup := func(t *testing.T) *oworld {
		x := newOriginWorld(t, func(o *originOpts) { o.noSibling = true })
		x.hist.set(originWWW, "a", histRec{histInNet, "2023-01-01", "2024-02-02"})
		return x
	}
	t.Run("443 answers: 80 is never asked", func(t *testing.T) {
		x := setup(t)
		https := x.historicalOrigin()
		http80 := x.plain(histInNet, 80, x.originHandler)
		x.mustRun()
		if wwwGets(https, "https") != 1 || wwwGets(http80, "http") != 0 {
			t.Errorf("https %d, http %d", wwwGets(https, "https"), wwwGets(http80, "http"))
		}
	})
	t.Run("443 refuses: one GET on 80", func(t *testing.T) {
		x := setup(t)
		http80 := x.plain(histInNet, 80, x.originHandler)
		x.mustRun()
		if got := wwwGets(http80, "http"); got != 1 {
			t.Errorf("http GETs = %d, want 1", got)
		}
		x.wantRow(histInNet, "medium", "historical", "title", "yes", "true") // the title alone, over http
	})
	t.Run("a TLS error on 443: 80 is not asked", func(t *testing.T) {
		x := setup(t)
		x.plain(histInNet, 443, x.originHandler) // plain HTTP where TLS is expected
		http80 := x.plain(histInNet, 80, x.originHandler)
		x.mustRun()
		if wwwGets(http80, "http") != 0 {
			t.Errorf("a TLS failure fell back to http: %d GETs", wwwGets(http80, "http"))
		}
		x.wantRow(histInNet, "low", "historical", "", "no", "true")
	})
	t.Run("a redirect confirms nothing and is not followed", func(t *testing.T) {
		x := setup(t)
		https := x.secure(histInNet, 443, selfFor(t, originWWW), func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.Host, originWWW) {
				http.Redirect(w, r, "https://www.example.com/home", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(siteBody("x")))
		})
		x.mustRun()
		x.wantRow(histInNet, "low", "historical", "", "no", "true")
		if got := https.count("/home"); got != 0 {
			t.Errorf("the redirect was followed %d times", got)
		}
	})
}

// --- findings that stop being current ---

// A finding is marked not current when the pair no longer qualifies: the hostname is no longer behind
// a CDN or WAF, the address becomes provider infrastructure, or the sibling no longer matches.
func TestOrigin_FindingGoesNotCurrent(t *testing.T) {
	t.Run("the hostname is no longer behind a CDN or WAF", func(t *testing.T) {
		x := newOriginWorld(t, func(o *originOpts) { o.byRange = true })
		x.mustRun()
		x.wantRow(siblingAddr, "medium", "sibling-certificate", "title", "yes", "true")
		x.set(func() { x.cfRanges = "104.16.0.0/13\n" })
		x.mustRun("--redo", "providerranges")
		if r := x.row(siblingAddr); r == nil || r["current"] != "false" {
			t.Errorf("row after the host left the CDN = %v", r)
		}
	})
	t.Run("the address becomes provider infrastructure", func(t *testing.T) {
		x := newOriginWorld(t, func(o *originOpts) { o.byRange = true })
		x.mustRun()
		x.wantRow(siblingAddr, "medium", "sibling-certificate", "title", "yes", "true")
		x.set(func() { x.cfRanges = "104.16.0.0/13\n203.0.113.8/29\n203.0.113.20/32\n" })
		x.mustRun("--redo", "providerranges")
		if r := x.row(siblingAddr); r == nil || r["current"] != "false" {
			t.Errorf("row after the address became a CDN's = %v", r)
		}
	})
	t.Run("the sibling no longer matches", func(t *testing.T) {
		x := newOriginWorld(t)
		x.mustRun()
		x.wantRow(siblingAddr, "medium", "sibling-certificate", "title", "yes", "true")
		x.set(func() {
			x.siblingCrt = selfSigned(t, leafSpec{cn: "origin.example.com", dns: []string{"origin.example.com"}})
		})
		x.mustRun("--redo", "httpprobe")
		if r := x.row(siblingAddr); r == nil || r["current"] != "false" {
			t.Errorf("row after the certificate stopped naming the host = %v", r)
		}
	})
}

// When --redo origincheck gets an answer that no longer confirms, the row stays current (its key
// does not change) but is a possible origin: low, not confirmed.
func TestOrigin_RedoThatFailsToConfirmLeavesAPossibleOrigin(t *testing.T) {
	x := newOriginWorld(t)
	x.mustRun()
	x.wantRow(siblingAddr, "medium", "sibling-certificate", "title", "yes", "true")
	x.set(func() { x.originRaw = originBadRaw })
	x.mustRun("--redo", "origincheck")
	x.wantRow(siblingAddr, "low", "sibling-certificate", "", "no", "true")
	if n := len(x.rows()); n != 1 {
		t.Errorf("rows = %d, want the one row to move, not a second", n)
	}
	if n := len(current(x.rows())); n != 1 {
		t.Errorf("current rows = %d", n)
	}
}

// --- the stages ---

// Without a SecurityTrails key dnshistory is not configured and nothing is asked of SecurityTrails,
// and origincheck runs over sibling-derived candidates.
func TestOrigin_NoKeyLeavesSiblingCandidatesOnly(t *testing.T) {
	x := newOriginWorld(t, func(o *originOpts) { o.noKey = true })
	x.hist.set(originWWW, "a", histRec{histInNet, "2023-01-01", "2024-02-02"})
	x.historicalOrigin()
	x.mustRun()
	if st, reason := stateOf(x.world, "dnshistory"); st != "not-configured" || reason != "no key" {
		t.Errorf("dnshistory state = %q (%q), want not-configured (no key)", st, reason)
	}
	if x.hist.askedCount() != 0 {
		t.Errorf("history was asked %d times", x.hist.askedCount())
	}
	for _, r := range x.table(eng, "resolutions.csv") {
		if strings.HasSuffix(r["type"], "-historical") {
			t.Errorf("a historical row without a key: %v", r)
		}
	}
	x.wantRow(siblingAddr, "medium", "sibling-certificate", "title", "yes", "true")
	if x.row(histInNet) != nil {
		t.Error("the historical address is a candidate without history")
	}
}

// dnshistory asks hostnames in name order up to dnshistory.max_hosts per run, the rest are deferred
// and counted in the summary, and a later run asks the next ones.
func TestDNSHistory_CapAndDeferredCount(t *testing.T) {
	x := newWeb(t)
	t.Setenv("NYX_KEYS_SECURITYTRAILS", securityTrailsKey)
	hist := &stHistory{records: map[string][]histRec{}}
	x.handle("api.securitytrails.com", hist.serve)
	x.names("www3.example.com", "www1.example.com", "www2.example.com", "plain.example.com")
	for _, n := range []string{"www1", "www2", "www3"} {
		x.dns.CNAME(n+".example.com", "x.global.fastly.net")
	}
	x.host("x.global.fastly.net", cdnAddr)
	x.host("plain.example.com", "203.0.113.30") // not behind a CDN: never asked
	x.owner("203.0.113.30", 64500, "ACME-NET")
	hist.set("www1.example.com", "a", histRec{histOutside, "2023-01-01", "2024-02-02"})
	x.owner(histOutside, 64500, "ACME-NET")

	x.mustRun("--passive", "--dnshistory-max-hosts", "1")
	if got := hist.askedHosts(); !slices.Equal(got, []string{"www1.example.com"}) {
		t.Errorf("first run asked %v, want www1 alone", got)
	}
	if n := deferredOf(t, x.h, "dnshistory"); n != 2 {
		t.Errorf("deferred = %d, want 2", n)
	}
	x.mustRun("--passive", "--dnshistory-max-hosts", "1")
	if got := hist.askedHosts(); !slices.Equal(got, []string{"www1.example.com", "www2.example.com"}) {
		t.Errorf("second run asked %v, want www2 next", got)
	}
	if n := deferredOf(t, x.h, "dnshistory"); n != 1 {
		t.Errorf("deferred after the second run = %d, want 1", n)
	}
	if slices.Contains(hist.askedHosts(), "plain.example.com") {
		t.Error("a host not behind a CDN was asked")
	}
}

// Under --passive origincheck is skipped, so nothing reaches any address, and dnshistory runs.
func TestOrigin_PassiveSkipsOriginCheckAndRunsDNSHistory(t *testing.T) {
	x := newOriginWorld(t)
	x.hist.set(originWWW, "a", histRec{histOutside, "2023-01-01", "2024-02-02"})
	x.historicalOrigin()
	if code := x.world.run("--passive", "--cidr", "198.51.100.0/24", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, reason := stateOf(x.world, "origincheck"); st != "not-configured" || reason != "passive-only" {
		t.Errorf("origincheck state = %q (%q), want not-configured (passive-only)", st, reason)
	}
	if st, _ := stateOf(x.world, "dnshistory"); st != "done" {
		t.Errorf("dnshistory state = %q, want done", st)
	}
	if x.sibling.hits() != 0 || x.cdn.hits() != 0 {
		t.Errorf("a target was contacted under --passive: sibling %d, cdn %d", x.sibling.hits(), x.cdn.hits())
	}
	x.wantRow(histOutside, "low", "historical", "", "no", "true")
}

// --- help and README ---

// The flags and stages are documented, and the severity list names both finding types.
func TestOrigin_Help(t *testing.T) {
	h := newHarness(t, defaultStageList()...)
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"--dnshistory-max-hosts", "--origincheck-max-candidates"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("help missing %s", want)
		}
	}
	topic := h.stagesHelp()
	if row := stageRow(topic, "dnshistory"); !strings.Contains(row, "securitytrails") || !strings.Contains(row, "third party") {
		t.Errorf("help stages row for dnshistory = %q", row)
	}
	if row := stageRow(topic, "origincheck"); !strings.Contains(row, "target") {
		t.Errorf("help stages row for origincheck = %q", row)
	}
	if code := h.execArgs("help", "findings"); code != 0 {
		t.Fatalf("help findings: exit %d", code)
	}
	for _, want := range []string{"origin-exposure", "confirmed", "possible"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("help findings does not list %q", want)
		}
	}
}

// The README states the one new request the target can receive, and why, and lists origincheck among
// the stages --passive skips, the new file and the settings.
func TestOrigin_ReadmeStatesTheBoundary(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	flat := strings.ToLower(strings.Join(strings.Fields(readme), " "))
	i := strings.Index(readme, "## Passive boundary")
	j := strings.Index(readme, "## Passive-only mode")
	if i < 0 || j < i {
		t.Fatal("README has no passive boundary section")
	}
	boundary := strings.ToLower(strings.Join(strings.Fields(readme[i:j]), " "))
	for _, want := range []string{"one get of `/` to an address it is already allowed to contact",
		"in-scope hostname as the server name and the host header", "whether a hostname behind a cdn or waf is also served directly"} {
		if !strings.Contains(boundary, want) {
			t.Errorf("the passive boundary does not say %q", want)
		}
	}
	passive := readme[j:min(len(readme), j+600)]
	if !strings.Contains(passive, "`origincheck`") {
		t.Errorf("the --passive stage list does not name origincheck: %q", passive)
	}
	for _, want := range []string{"risk-origin-exposure.csv", "dnshistory.max_hosts", "origincheck.max_candidates", "a-historical",
		"historical_first_seen", "hostnames for `dnshistory`"} {
		if !strings.Contains(flat, strings.ToLower(want)) {
			t.Errorf("README does not mention %q", want)
		}
	}
}
