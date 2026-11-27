package cli_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/recon/run"
)

// Hostnames read from TCP banners (the ports procedure) and from the origin-check answer (the
// origincheck procedure). A name these tests plant has no address unless it says otherwise, so
// that probing it does not change the requests and connections they count.

// wantTaken checks that a name was observed as a hostname by the procedure, is listed in
// subdomains.txt and was resolved.
func wantTaken(t *testing.T, x *web, procedure, name string) {
	t.Helper()
	if got := x.observedBy("hostname", procedure); !slices.Contains(got, name) {
		t.Errorf("%s did not observe the hostname %s; it observed %v", procedure, name, got)
	}
	if got := x.lines(eng, "subdomains.txt"); !slices.Contains(got, name) {
		t.Errorf("subdomains.txt does not list %s: %v", name, got)
	}
	if got := x.completedKeys("resolve"); !slices.Contains(got, name) {
		t.Errorf("resolve has no job for %s", name)
	}
}

// hostnameKeys are the keys of every hostname record, whoever observed it.
func hostnameKeys(x *web) []string {
	x.t.Helper()
	return queryStrings(x.t, x.h.openDB(eng), "SELECT DISTINCT key FROM observations WHERE kind='hostname'")
}

// wantNotRecorded checks that a name is no hostname record, is not listed in subdomains.txt, and
// is neither a candidate nor a third party.
func wantNotRecorded(t *testing.T, x *web, name string) {
	t.Helper()
	if slices.Contains(hostnameKeys(x), name) {
		t.Errorf("%s is a hostname record", name)
	}
	if slices.Contains(x.lines(eng, "subdomains.txt"), name) {
		t.Errorf("subdomains.txt lists %s", name)
	}
	for _, file := range []string{"candidates.csv", "third-parties.csv"} {
		if strings.Contains(x.file(eng, file), name) {
			t.Errorf("%s names %s:\n%s", file, name, x.file(eng, file))
		}
	}
}

// storedBanner is the banner of an open_port record, decoded.
func storedBanner(t *testing.T, x *web, key string) string {
	t.Helper()
	raw, ok := x.obsAttrs(eng, "open_port")[key]
	if !ok {
		t.Fatalf("no open_port record for %s", key)
	}
	var a struct {
		Banner string `json:"banner"`
	}
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatalf("%s: %v (%q)", key, err, raw)
	}
	back, err := strconv.Unquote(`"` + a.Banner + `"`)
	if err != nil {
		t.Fatalf("%s: banner %q does not decode: %v", key, a.Banner, err)
	}
	return back
}

// withPorts puts the real ports procedure into a web world's registry, as newPorts does.
func withPorts(t *testing.T, x *web) *pworld {
	t.Helper()
	var ports run.Procedure
	for _, s := range defaultProcedureList() {
		if s.Name() == "ports" {
			ports = s
		}
	}
	procedures := slices.DeleteFunc(slices.Clone(x.h.procedures), func(s run.Procedure) bool { return s.Name() == "fakeports" })
	i := slices.IndexFunc(procedures, func(s run.Procedure) bool { return s.Name() == "crawl" })
	if ports == nil || i < 0 {
		t.Fatal("the registry has no ports or no crawl procedure")
	}
	x.h.procedures = slices.Insert(procedures, i+1, ports)
	x.h.eopts.BannerWait = 300 * time.Millisecond
	return &pworld{web: x}
}

// sameRequests fails when two sites did not receive the same requests, in any order.
func sameRequests(t *testing.T, what string, got, want *site) {
	t.Helper()
	list := func(s *site) []string {
		var out []string
		for _, r := range s.requests() {
			out = append(out, fmt.Sprintf("%s %s %s tls=%v", r.Method, r.Host, r.URI, r.TLS))
		}
		slices.Sort(out)
		return out
	}
	if g, w := list(got), list(want); !slices.Equal(g, w) {
		t.Errorf("%s received other requests with names in the text:\n got %v\nwant %v", what, g, w)
	}
}

// --- banners ---

// A name in a banner is taken whichever hostnames its address serves, including a name the
// address already serves.
func TestBannerNames_AddressThatServesAHostname(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.app() // app.example.com at appHost
	srv := p.serve(appHost, 25, "220 app.example.com ESMTP Postfix; relay mx1.example.com\r\n")
	p.sweep([]int{25})

	if srv.conns.Load() != 1 {
		t.Fatalf("the SMTP port was contacted %d times, want 1", srv.conns.Load())
	}
	wantTaken(t, p.web, "ports", "mx1.example.com")
	if got := p.observedBy("hostname", "ports"); !slices.Contains(got, "app.example.com") {
		t.Errorf("ports did not observe app.example.com, which its address already serves: %v", got)
	}
}

// An address that serves no hostname (one inside an in-scope netblock) gives its banner's names too.
func TestBannerNames_AddressThatServesNoHostname(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	srv := p.serve("198.51.100.1", 25, "220 relay.example.com ESMTP\r\n")
	p.sweep([]int{25}, "--cidr", "198.51.100.1/32")

	if srv.conns.Load() != 1 {
		t.Fatalf("the netblock address was contacted %d times, want 1", srv.conns.Load())
	}
	if r := find(p.table(eng, "ips.csv"), "ip", "198.51.100.1"); r != nil && r["hostnames"] != "" {
		t.Errorf("precondition: the address serves no hostname, but ips.csv has %v", r)
	}
	wantTaken(t, p.web, "ports", "relay.example.com")
}

// The banner read by the job that settles a port a third party reported is read like any other.
func TestBannerNames_ReportedRecheck(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.app()
	ports := []int{25}
	p.sweep(ports) // appHost:25 refuses, and nothing is reported yet

	f := p.shodan()
	f.setHost(appHost, hostJSON(appHost, nil, tcp(25, "")))
	srv := p.serve(appHost, 25, "220 recheck.example.com ESMTP\r\n")
	p.sweep(ports)

	if !slices.Contains(p.checked(), appHost+":25|reported") || srv.conns.Load() != 1 {
		t.Fatalf("precondition: one recheck of the reported port; jobs %v, connections %d", p.checked(), srv.conns.Load())
	}
	wantTaken(t, p.web, "ports", "recheck.example.com")
}

// A banner only Shodan reports is not searched.
func TestBannerNames_ShodanBannerIsNotRead(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	f := p.shodan()
	p.app()
	f.setHost(appHost, hostJSON(appHost, nil,
		tcp(2525, "220 shodan-smtp.example.com ESMTP\r\n"),
		tcp(8080, "HTTP/1.1 302 Found\r\nLocation: https://shodan-web.example.com/\r\n")))
	never := p.canary(appHost, []int{2525, 8080})
	p.sweep([]int{7001})

	if a := p.obsAttrs(eng, "reported_port")[appHost+":2525"]; !strings.Contains(a, "shodan-smtp.example.com") {
		t.Fatalf("precondition: Shodan's banner is stored, got %q", a)
	}
	if n := never.conns.Load(); n != 0 {
		t.Errorf("a port only Shodan reported was dialled %d times", n)
	}
	for _, n := range []string{"shodan-smtp.example.com", "shodan-web.example.com"} {
		wantNotRecorded(t, p.web, n)
	}
}

// A name in scope that resolves to a web service, found only in a banner, is probed like any other.
func TestBannerNames_FoundNameIsProbed(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.app()
	p.serve(appHost, 25, "220 portal.example.com ESMTP\r\n")
	p.host("portal.example.com", "203.0.113.41")
	p.owner("203.0.113.41", 64500, "ACME-NET")
	portal := p.plain("203.0.113.41", 80, page("<title>Portal</title>"))
	p.sweep([]int{25})

	wantTaken(t, p.web, "ports", "portal.example.com")
	if portal.hits() == 0 {
		t.Error("the web service of a name found in a banner was never probed")
	}
	if find(p.services(), "url", "http://portal.example.com") == nil {
		t.Errorf("web-services.csv has no http://portal.example.com: %v", p.serviceURLs())
	}
}

// Reading a banner sends nothing: with names in the banners, every port gets the same
// connections as without them, nothing is sent to a banner port, and a name under no root is
// never contacted.
func TestBannerNames_ReadingSendsNothing(t *testing.T) {
	t.Parallel()
	type result struct {
		seq            []string
		conns, bytes   int64
		canary         int32
		portsHostnames []string
	}
	sweep := func(t *testing.T, named bool) result {
		t.Helper()
		p := newPorts(t)
		p.app()
		banner, relay := "220 ESMTP ready\r\n", "220 relay ready\r\n"
		var canary *portSrv
		if named {
			banner = "220 mx1.example.com ESMTP; backup mx2.example.com; peer mail.other.net\r\n"
			relay = "220 relay.example.com ESMTP\r\n"
			p.dns.A("mail.other.net", "192.0.2.66")
			canary = p.canary("192.0.2.66", []int{25, 80, 443})
		}
		srv := p.serve(appHost, 25, banner)
		rel := p.serve("198.51.100.1", 25, relay)
		p.sweep([]int{25}, "--cidr", "198.51.100.1/32")
		r := result{seq: p.sequence(), conns: int64(srv.conns.Load() + rel.conns.Load()), bytes: srv.bytes.Load() + rel.bytes.Load(),
			portsHostnames: p.observedBy("hostname", "ports")}
		if canary != nil {
			r.canary = canary.conns.Load()
		}
		slices.Sort(r.seq)
		return r
	}
	plain := sweep(t, false)
	named := sweep(t, true)

	if !slices.Equal(named.seq, plain.seq) || named.conns != plain.conns {
		t.Errorf("connections with names in the banners = %v (%d), without = %v (%d)", named.seq, named.conns, plain.seq, plain.conns)
	}
	if named.bytes != 0 {
		t.Errorf("%d bytes were sent to a banner port", named.bytes)
	}
	if named.canary != 0 {
		t.Errorf("an address of a name under no root was contacted %d times", named.canary)
	}
	for _, n := range []string{"mx1.example.com", "mx2.example.com", "relay.example.com"} {
		if !slices.Contains(named.portsHostnames, n) {
			t.Errorf("ports did not take %s: %v", n, named.portsHostnames)
		}
	}
}

// A name under no root in a banner gives nothing: no hostname, no candidate and no third party.
func TestBannerNames_NameUnderNoRootIsIgnored(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.app()
	p.serve(appHost, 25, "220 inbound.example.com ESMTP; relaying for mail.other.net\r\n")
	p.sweep([]int{25})

	wantTaken(t, p.web, "ports", "inbound.example.com")
	wantNotRecorded(t, p.web, "mail.other.net")
}

// A banner that filled the banner read is cut: the name that runs up to the cut is not taken,
// and the other names in it are.
func TestBannerNames_NameAtTheCutIsNotTaken(t *testing.T) {
	t.Parallel()
	p := newPorts(t)
	p.app()
	head, tail := "220 early.example.com ESMTP ", "cutname.example.com"
	banner := head + strings.Repeat(" ", 1024-len(head)-len(tail)) + tail
	p.serve(appHost, 25, banner+".evil.net\r\n") // the service's real name runs past the read
	p.sweep([]int{25})

	if got := storedBanner(t, p.web, appHost+":25"); got != banner {
		t.Fatalf("precondition: the banner read is the first 1,024 bytes; got %d bytes ending %q", len(got), got[max(0, len(got)-30):])
	}
	wantTaken(t, p.web, "ports", "early.example.com")
	if slices.Contains(hostnameKeys(p.web), "cutname.example.com") || slices.Contains(p.lines(eng, "subdomains.txt"), "cutname.example.com") {
		t.Error("the name that runs up to the end of a full banner was taken")
	}
}

// A name only permutations found becomes a seed for name guessing once its address's banner
// spells it, as ports is then a second producer of it. The same name in its own web page does
// not make it one (see also TestRedirect_PermutationOnlyNameIsNeverSeededByItsOwnService).
func TestBannerNames_PermutationOnlyNameInABannerBecomesASeed(t *testing.T) {
	t.Parallel()
	seeded := func(x *web) bool {
		return slices.ContainsFunc(x.completedKeys("permutations"), func(k string) bool {
			return strings.HasPrefix(k, "seed|api-dev.example.com|")
		})
	}
	t.Run("in its address's banner", func(t *testing.T) {
		t.Parallel()
		p := newPorts(t)
		p.perms = true
		wl := writeFile(t, t.TempDir(), "words.txt", "dev\n")
		p.names("api.example.com")
		p.host("api.example.com", "203.0.113.5")
		p.owner("203.0.113.5", 64500, "ACME-NET")
		p.host("api-dev.example.com", "203.0.113.6") // a permutation that exists
		p.owner("203.0.113.6", 64500, "ACME-NET")
		srv := p.serve("203.0.113.6", 25, "220 api-dev.example.com ESMTP\r\n")
		p.sweep([]int{25}, "--wordlist", wl)

		if srv.conns.Load() != 1 {
			t.Fatalf("precondition: the permutation's address was swept once, got %d", srv.conns.Load())
		}
		if got := p.observedBy("hostname", "ports"); !slices.Contains(got, "api-dev.example.com") {
			t.Errorf("ports did not observe api-dev.example.com from its banner: %v", got)
		}
		if !seeded(p.web) {
			t.Errorf("api-dev.example.com did not become a seed; permutations jobs %v", p.completedKeys("permutations"))
		}
	})
	t.Run("in its own web page", func(t *testing.T) {
		t.Parallel()
		x := newWeb(t)
		x.perms = true
		wl := writeFile(t, t.TempDir(), "words.txt", "dev\n")
		x.names("api.example.com")
		x.host("api.example.com", "203.0.113.5")
		x.host("api-dev.example.com", "203.0.113.6")
		s := x.secure("203.0.113.6", 443, selfFor(t, "api-dev.example.com"),
			page(`<title>Dev</title><p>Welcome to api-dev.example.com</p><a href="https://api-dev.example.com/about">about</a>`))
		x.mustRun("--wordlist", wl)

		if s.hits() == 0 {
			t.Fatal("precondition: the permutation-only name was probed")
		}
		if seeded(x) {
			t.Errorf("api-dev.example.com became a seed through its own page; permutations jobs %v", x.completedKeys("permutations"))
		}
		for _, proc := range []string{"httpprobe", "crawl", "jsparse"} {
			if got := x.observedBy("hostname", proc); slices.Contains(got, "api-dev.example.com") {
				t.Errorf("%s observed the host's own name from its page: %v", proc, got)
			}
		}
	})
}

// --- the origin-check answer ---

// originPage is the fronted site's page with extra text in its body.
func originPage(extra string) string {
	return "<html><head><title>" + acmeTitle + "</title></head><body>" + strings.Repeat("Acme ", 200) + extra + "</body></html>"
}

// A name in the origin-check answer is taken; the pair's own host, an input root and a name under
// no root are not.
func TestOriginCheckNames_BodyNamesAreTaken(t *testing.T) {
	t.Parallel()
	x := newOriginWorld(t)
	x.set(func() {
		x.originRaw = originPage(`<!-- staging: staging-origin.example.com; live: https://www.example.com/ on example.com; cdn: edge.other.net -->`)
	})
	x.mustRun()

	if got := wwwGets(x.sibling, "https"); got != 1 {
		t.Fatalf("precondition: one origin check, got %d", got)
	}
	wantTaken(t, x.web, "origincheck", "staging-origin.example.com")
	got := x.observedBy("hostname", "origincheck")
	for _, n := range []string{"www.example.com", "example.com"} {
		if slices.Contains(got, n) {
			t.Errorf("origincheck observed %s (the pair's own host or an input root): %v", n, got)
		}
	}
	wantNotRecorded(t, x.web, "edge.other.net")
}

// Reading the origin-check answer sends nothing: with names in it, the sites get the same
// requests as without them, and a name under no root is never contacted.
func TestOriginCheckNames_ReadingSendsNothing(t *testing.T) {
	t.Parallel()
	build := func(t *testing.T, named bool) (*oworld, *site) {
		t.Helper()
		x := newOriginWorld(t)
		extra := ""
		var canary *site
		if named {
			extra = `<!-- backend-a.example.com backend-b.example.com edge.other.net -->`
			x.dns.A("edge.other.net", "192.0.2.66")
			canary = x.silent("192.0.2.66", 80)
			x.silent("192.0.2.66", 443)
		}
		x.set(func() { x.originRaw = originPage(extra) })
		x.mustRun()
		return x, canary
	}
	plain, _ := build(t, false)
	named, canary := build(t, true)

	if got := wwwGets(named.sibling, "https"); got != 1 {
		t.Fatalf("precondition: one origin check, got %d", got)
	}
	sameRequests(t, "the origin", named.sibling, plain.sibling)
	sameRequests(t, "the CDN", named.cdn, plain.cdn)
	if n := canary.conns.Load(); n != 0 {
		t.Errorf("the address of a name under no root was contacted %d times", n)
	}
	got := named.observedBy("hostname", "origincheck")
	for _, n := range []string{"backend-a.example.com", "backend-b.example.com"} {
		if !slices.Contains(got, n) {
			t.Errorf("origincheck did not take %s: %v", n, got)
		}
	}
}

// standalone200 matches the number 200 on its own, not as the end of 1,200.
var standalone200 = regexp.MustCompile(`(^|[^0-9,])200([^0-9,]|$)`)

// originCapWorld is the origin world whose fronted page names five hosts and whose origin-check
// answer names 1,200 others.
func originCapWorld(t *testing.T) (x *oworld, front, checked []string) {
	t.Helper()
	x = newOriginWorld(t)
	for i := 1; i <= 5; i++ {
		front = append(front, fmt.Sprintf("front%d.example.com", i))
	}
	for i := 1; i <= 1200; i++ {
		checked = append(checked, fmt.Sprintf("oc%04d.example.com", i))
	}
	x.set(func() {
		// The fronted service's own text names its five, which use places of its own.
		x.cdnTitle = acmeTitle + "</title><!-- " + strings.Join(front, " ") + " --><title>"
		x.originRaw = originPage("<!-- " + strings.Join(checked, " ") + " -->")
	})
	return x, front, checked
}

// countIn is the number of names in got that are in want.
func countIn(got, want []string) int {
	n := 0
	for _, g := range got {
		if slices.Contains(want, g) {
			n++
		}
	}
	return n
}

// The origin-check answer has a cap of its own: of 1,200 names it takes 1,000, without using the
// fronted service's places, and the run ends with one warning naming the host, the address, the
// 200 left out and the cap. Under --json the warning is in the envelope's warnings.
func TestOriginCheckNames_CapOfItsOwn(t *testing.T) {
	t.Parallel()
	check := func(t *testing.T, x *oworld, front, checked []string) {
		t.Helper()
		if got := wwwGets(x.sibling, "https"); got != 1 {
			t.Fatalf("precondition: one origin check, got %d", got)
		}
		if n := countIn(x.observedBy("hostname", "httpprobe"), front); n != len(front) {
			t.Errorf("precondition: the probe took %d of the fronted page's %d names", n, len(front))
		}
		if n := countIn(x.observedBy("hostname", "origincheck"), checked); n != 1000 {
			t.Errorf("origincheck took %d of the answer's 1,200 names, want 1,000", n)
		}
		if n := countIn(x.lines(eng, "subdomains.txt"), checked); n != 1000 {
			t.Errorf("subdomains.txt lists %d of the answer's names, want 1,000", n)
		}
	}
	matches := func(m string) bool {
		return strings.Contains(m, originWWW) && strings.Contains(m, siblingAddr) && strings.Contains(m, "1,000") && standalone200.MatchString(m)
	}
	t.Run("json", func(t *testing.T) {
		t.Parallel()
		x, front, checked := originCapWorld(t)
		x.mustRun()
		check(t, x, front, checked)
		capped := x.h.messages("warning", "1,000")
		if len(capped) != 1 || !matches(capped[0]) {
			t.Errorf("warnings about the cap = %q, want one naming %s, %s, 200 and 1,000", capped, originWWW, siblingAddr)
		}
		if env := x.h.envelope(); !slices.ContainsFunc(env.Meta.Warnings, matches) {
			t.Errorf("the envelope's warnings = %q, want the origin check's", env.Meta.Warnings)
		}
	})
	t.Run("console", func(t *testing.T) {
		t.Parallel()
		x, front, checked := originCapWorld(t)
		x.fill()
		code := x.h.exec("--authorised", "--rate-per-host", "1000", "--rate-per-source", "1000", "--rate-dns", "100000",
			"--no-permutations", "--cidr", "198.51.100.0/24", "example.com")
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, x.h.stderr.String())
		}
		check(t, x, front, checked)
		var capped []string
		for _, m := range x.h.logMsgs("WARN") {
			if strings.Contains(m, "1,000") {
				capped = append(capped, m)
			}
		}
		if len(capped) != 1 || !matches(capped[0]) {
			t.Errorf("WARN lines about the cap = %q, want one naming %s, %s, 200 and 1,000", capped, originWWW, siblingAddr)
		}
	})
}

// --- passive and unauthorised runs ---

// Under --passive, and without --authorised, the procedures that read responses and banners do
// not run: nothing is contacted and no name in the fixtures is recorded.
func TestTextNames_PassiveAndUnauthorisedReadNothing(t *testing.T) {
	t.Parallel()
	planted := []string{"front-page.example.com", "origin-text.example.com", "banner-text.example.com"}
	readers := []string{"httpprobe", "crawl", "jsparse", "origincheck", "ports"}
	cases := []struct {
		name, reason string
		run          func(p *pworld) int
	}{
		{"passive", "passive-only", func(p *pworld) int {
			return p.run("--passive", "--cidr", "198.51.100.0/24", "--ports", "25")
		}},
		{"not authorised", "no authorisation", func(p *pworld) int {
			p.fill()
			return p.world.run("--rate-per-host", "1000", "--no-permutations", "--cidr", "198.51.100.0/24", "--ports", "25", "example.com")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			x := newOriginWorld(t)
			x.set(func() {
				x.cdnTitle = acmeTitle + `</title><script>var api = "https:\/\/front-page.example.com\/v1";</script><title>`
				x.originRaw = originPage("<!-- origin-text.example.com -->")
			})
			p := withPorts(t, x.web)
			banner := p.serve(rootIP, 25, "220 banner-text.example.com ESMTP\r\n")
			if code := c.run(p); code != 0 {
				t.Fatalf("exit %d\n%s", code, x.h.stdout.String())
			}
			for _, name := range readers {
				if st, why := stateOf(x.world, name); st != "not-configured" || why != c.reason {
					t.Errorf("%s = %s (%s), want not-configured (%s)", name, st, why, c.reason)
				}
			}
			if x.cdn.hits() != 0 || x.sibling.hits() != 0 || banner.conns.Load() != 0 {
				t.Errorf("a target was contacted: cdn %d, origin %d, banner port %d", x.cdn.hits(), x.sibling.hits(), banner.conns.Load())
			}
			for _, n := range planted {
				wantNotRecorded(t, x.web, n)
			}
		})
	}
}
