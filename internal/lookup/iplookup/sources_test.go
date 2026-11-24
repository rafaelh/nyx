package iplookup

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
)

// keysSet reports whether every key of the source holds a value (a non-null one).
func keysSet(r Record, s Source) bool {
	switch s {
	case SourceCymru:
		return r.ASN != nil && r.ASName != nil && r.ASPrefix != nil
	case SourceRDAP:
		return r.RDAPNetblock != nil && r.RDAPOrg != nil && r.RDAPRegistry != nil
	case SourcePTR:
		return r.PTR != nil
	case SourceRIPEstat:
		return r.GeoCountry != nil && r.GeoCity != nil
	case SourceInternetDB:
		return r.InternetDBPorts != nil && r.InternetDBHostnames != nil && r.InternetDBTags != nil && r.InternetDBCPEs != nil && r.InternetDBVulns != nil
	case SourceHackerTarget:
		return r.ReverseIP != nil && r.ReverseIPCount != nil
	case SourceProbe:
		return false
	}
	return false
}

// keysNull reports whether every key of the source is null.
func keysNull(r Record, s Source) bool {
	switch s {
	case SourceCymru:
		return r.ASN == nil && r.ASName == nil && r.ASPrefix == nil
	case SourceRDAP:
		return r.RDAPNetblock == nil && r.RDAPOrg == nil && r.RDAPRegistry == nil
	case SourcePTR:
		return r.PTR == nil
	case SourceRIPEstat:
		return r.GeoCountry == nil && r.GeoCity == nil
	case SourceInternetDB:
		return r.InternetDBPorts == nil && r.InternetDBHostnames == nil && r.InternetDBTags == nil && r.InternetDBCPEs == nil && r.InternetDBVulns == nil
	case SourceHackerTarget:
		return r.ReverseIP == nil && r.ReverseIPCount == nil
	case SourceProbe:
		return true
	}
	return false
}

var defaultSources = []Source{SourceCymru, SourceRDAP, SourcePTR, SourceRIPEstat, SourceInternetDB, SourceHackerTarget}

func TestSources_FullRecord(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	w.populate(pubAddr)
	res := only(t, w.lookup(pubAddr))
	r := res.Record
	if r.Address != pubAddr || r.Kind != addrkind.Public || r.Hostnames == nil || len(r.Failures) != 0 {
		t.Fatalf("record = %+v", r)
	}
	if r.ASN == nil || *r.ASN != 15169 || deref(r.ASName) != "GOOGLE" || deref(r.ASPrefix) != "8.8.4.0/24" {
		t.Errorf("owner = %v %s %s", r.ASN, deref(r.ASName), deref(r.ASPrefix))
	}
	if deref(r.RDAPNetblock) != "8.8.4.0/24" || deref(r.RDAPOrg) != "Google LLC" || deref(r.RDAPRegistry) != "arin" {
		t.Errorf("registration = %s %s %s", deref(r.RDAPNetblock), deref(r.RDAPOrg), deref(r.RDAPRegistry))
	}
	if !slices.Equal(r.PTR, []string{"dns.google"}) {
		t.Errorf("ptr = %v, want one cleaned name", r.PTR)
	}
	if deref(r.Provider) != "gcp" || deref(r.ProviderClass) != "hyperscaler" {
		t.Errorf("provider = %s %s, want the provider data's answer for AS15169", deref(r.Provider), deref(r.ProviderClass))
	}
	if deref(r.GeoCountry) != "US" || deref(r.GeoCity) != "Mountain View" {
		t.Errorf("geo = %s %s, want the location that covers most", deref(r.GeoCountry), deref(r.GeoCity))
	}
	if !slices.Equal(r.InternetDBPorts, []int{53, 443}) ||
		!slices.Equal(r.InternetDBHostnames, []string{"a.example", "z.example"}) ||
		!slices.Equal(r.InternetDBTags, []string{"cloud", "self-signed"}) ||
		!slices.Equal(r.InternetDBCPEs, []string{"cpe:/a:a", "cpe:/a:b"}) ||
		!slices.Equal(r.InternetDBVulns, []string{"CVE-2020-1", "CVE-2020-2"}) {
		t.Errorf("internetdb = %v %v %v %v %v", r.InternetDBPorts, r.InternetDBHostnames, r.InternetDBTags, r.InternetDBCPEs, r.InternetDBVulns)
	}
	if !slices.Equal(r.ReverseIP, []string{"a.example.com", "b.example.com"}) || r.ReverseIPCount == nil || *r.ReverseIPCount != 2 {
		t.Errorf("reverse ip = %v %v", r.ReverseIP, r.ReverseIPCount)
	}
	if !slices.Equal(res.Asked, defaultSources) {
		t.Errorf("asked = %v, want %v", res.Asked, defaultSources)
	}
}

func TestSources_HostnamesAreKept(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "asn")
	w.populate(pubAddr)
	res := Lookup(w.ctx(), w.cfg, Resolved{Addresses: []Address{{Addr: addr(pubAddr), Hostnames: []string{"a.example.com", "b.example.com"}, Found: FoundPublicDNS}}})
	if got := only(t, res).Record.Hostnames; !slices.Equal(got, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("hostnames = %v", got)
	}
}

// A source that knows nothing of the address has answered: its keys are empty, not null, and it
// is no failure.
func TestSources_EmptyAnswersAreAnswers(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	w.bootstrapped()
	w.http.on(hackerTargetURL(pubAddr), 200, "No records found")
	// Everything else is the default: Cymru and PTR say NXDOMAIN and the rest answer 404.
	res := only(t, w.lookup(pubAddr))
	r := res.Record
	if len(r.Failures) != 0 {
		t.Fatalf("failures = %+v", r.Failures)
	}
	if !keysNull(r, SourceCymru) || !keysNull(r, SourceRDAP) || !keysNull(r, SourceRIPEstat) {
		t.Errorf("single values are not null: %+v", r)
	}
	if r.PTR == nil || len(r.PTR) != 0 {
		t.Errorf("ptr = %#v, want []", r.PTR)
	}
	for name, l := range map[string][]string{"hostnames": r.InternetDBHostnames, "tags": r.InternetDBTags, "cpes": r.InternetDBCPEs, "vulns": r.InternetDBVulns, "reverse": r.ReverseIP} {
		if l == nil || len(l) != 0 {
			t.Errorf("%s = %#v, want []", name, l)
		}
	}
	if r.InternetDBPorts == nil || len(r.InternetDBPorts) != 0 {
		t.Errorf("ports = %#v, want []", r.InternetDBPorts)
	}
	if r.ReverseIPCount == nil || *r.ReverseIPCount != 0 {
		t.Errorf("reverse_ip_count = %v, want 0", r.ReverseIPCount)
	}
	if !slices.Equal(res.Asked, defaultSources) {
		t.Errorf("asked = %v; an unknown owner is still asked everything", res.Asked)
	}
}

type failCase struct {
	name      string
	src       Source
	url       string
	reply     fakeReply
	code      clierr.Code
	transient bool
}

func failCases() []failCase {
	var cs []failCase
	for _, s := range []struct {
		src Source
		url string
	}{
		{SourceRIPEstat, ripestatURL(pubAddr)},
		{SourceInternetDB, internetDBURL(pubAddr)},
		{SourceHackerTarget, hackerTargetURL(pubAddr)},
		{SourceRDAP, arinBase + "ip/" + pubAddr},
	} {
		if s.src != SourceHackerTarget {
			cs = append(cs, failCase{string(s.src) + " 429", s.src, s.url, fakeReply{status: 429}, clierr.RateLimited, true})
		}
		cs = append(cs,
			failCase{string(s.src) + " 500", s.src, s.url, fakeReply{status: 500, body: "boom"}, clierr.UpstreamError, true},
			failCase{string(s.src) + " truncated", s.src, s.url, fakeReply{status: 200, body: `{"ports":[`, truncated: true}, clierr.UpstreamError, true},
			failCase{string(s.src) + " transport", s.src, s.url, fakeReply{err: errors.New("connection reset")}, clierr.NetworkError, true},
		)
		if s.src == SourceHackerTarget {
			cs = append(cs, failCase{string(s.src) + " malformed", s.src, s.url, fakeReply{status: 200, body: "<html>not a list</html>"}, clierr.UpstreamError, true})
		} else {
			cs = append(cs, failCase{string(s.src) + " malformed", s.src, s.url, fakeReply{status: 200, body: `{"ports": [80, `}, clierr.UpstreamError, true})
		}
	}
	return cs
}

func TestSources_FailuresLeaveOnlyTheirKeysNull(t *testing.T) {
	t.Parallel()
	for _, tc := range failCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, false, "all")
			w.populate(pubAddr)
			w.http.set(tc.url, tc.reply)
			res := only(t, w.lookup(pubAddr))
			r := res.Record
			f, ok := failureOf(r, tc.src)
			if !ok || len(r.Failures) != 1 || f.Code != tc.code || f.Transient != tc.transient || f.Quota || f.Message == "" {
				t.Fatalf("failures = %+v, want one %s %s", r.Failures, tc.src, tc.code)
			}
			for _, s := range defaultSources {
				switch {
				case s == tc.src && !keysNull(r, s):
					t.Errorf("%s failed but its keys are not null: %+v", s, r)
				case s != tc.src && !keysSet(r, s):
					t.Errorf("%s did not fail but its keys are not whole: %+v", s, r)
				}
			}
			if !slices.Equal(res.Asked, defaultSources) {
				t.Errorf("asked = %v", res.Asked)
			}
		})
	}
}

func TestSources_HangIsATimeout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		src Source
		url string
	}{
		{SourceRIPEstat, ripestatURL(pubAddr)},
		{SourceInternetDB, internetDBURL(pubAddr)},
		{SourceRDAP, bootstrapURL4},
	} {
		t.Run(string(tc.src), func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, false, "all")
			w.populate(pubAddr)
			w.http.set(tc.url, fakeReply{hang: true})
			ctx, cancel := contextWithTimeout(300 * time.Millisecond)
			defer cancel()
			r := only(t, w.lookupCtx(ctx, pubAddr)).Record
			f, ok := failureOf(r, tc.src)
			if !ok || f.Code != clierr.Timeout || !f.Transient {
				t.Errorf("failure = %+v (%v), want transient TIMEOUT", f, ok)
			}
			if !keysNull(r, tc.src) {
				t.Errorf("%s keys are not null", tc.src)
			}
		})
	}
}

func TestSources_DNSFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		src  Source
		set  func(w *world)
	}{
		{"cymru servfail", SourceCymru, func(w *world) {
			w.dns.set(originName(pubAddr), egress.TypeTXT, egress.DNSResult{RCode: egress.RCodeServFail})
		}},
		{"cymru no response", SourceCymru, func(w *world) {
			w.dns.setErr(originName(pubAddr), egress.TypeTXT, errors.New("no response from any resolver"))
		}},
		{"ptr servfail", SourcePTR, func(w *world) {
			w.dns.set(ptrName(pubAddr), egress.TypePTR, egress.DNSResult{RCode: egress.RCodeServFail})
		}},
		{"ptr no response", SourcePTR, func(w *world) {
			w.dns.setErr(ptrName(pubAddr), egress.TypePTR, errors.New("no response from any resolver"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, false, "all")
			w.populate(pubAddr)
			tc.set(w)
			r := only(t, w.lookup(pubAddr)).Record
			f, ok := failureOf(r, tc.src)
			if !ok || f.Code != clierr.NetworkError || !f.Transient {
				t.Errorf("failure = %+v (%v), want transient NETWORK_ERROR", f, ok)
			}
			if !keysNull(r, tc.src) {
				t.Errorf("%s keys are not null: %+v", tc.src, r)
			}
			if tc.src == SourcePTR && !keysSet(r, SourceHackerTarget) {
				t.Error("a PTR failure took the other sources with it")
			}
			if tc.src == SourceCymru {
				// Without the owner, the shared check cannot be made, so HackerTarget is not asked.
				if w.http.count("https://api.hackertarget.com") != 0 || len(r.Failures) != 1 {
					t.Errorf("hackertarget asked without an owner; failures %+v", r.Failures)
				}
				if r.Provider != nil {
					t.Error("a provider was given without an owner")
				}
			}
		})
	}
}

// The origin answered but the holder's name did not: the AS number and prefix are kept.
func TestSources_HolderNameFailureKeepsTheOrigin(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "asn,as_name,as_prefix")
	w.populate(pubAddr)
	w.dns.set("AS15169.asn.cymru.com", egress.TypeTXT, egress.DNSResult{RCode: egress.RCodeServFail})
	r := only(t, w.lookup(pubAddr)).Record
	if r.ASN == nil || deref(r.ASPrefix) != "8.8.4.0/24" || r.ASName != nil {
		t.Errorf("owner = %v %s %s", r.ASN, deref(r.ASPrefix), deref(r.ASName))
	}
	if f, ok := failureOf(r, SourceCymru); !ok || f.Code != clierr.NetworkError {
		t.Errorf("failure = %+v, %v", f, ok)
	}
}

// A slow AS-name lookup cannot block provider/reverse-IP work, which only needs the known AS
// number.
func TestSources_HackerTargetDoesNotWaitForTheHolderName(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "as_name,provider,reverse_ip,reverse_ip_count")
	w.populate(pubAddr)
	w.dns.setHang("AS15169.asn.cymru.com", egress.TypeTXT)
	ctx, cancel := contextWithTimeout(time.Second)
	defer cancel()
	r := only(t, w.lookupCtx(ctx, pubAddr)).Record
	if w.http.count(hackerTargetURL(pubAddr)) != 1 || r.ReverseIP == nil || r.ReverseIPCount == nil {
		t.Errorf("HackerTarget was not asked while the holder name hung: reverse_ip %v", r.ReverseIP)
	}
	if f, ok := failureOf(r, SourceCymru); !ok || f.Code != clierr.Timeout || r.ASN == nil || r.ASName != nil {
		t.Errorf("cymru failure = %+v, %v; asn %v, as_name %s", f, ok, r.ASN, deref(r.ASName))
	}
	if r.Failed(SourceHackerTarget) {
		t.Errorf("failures = %+v", r.Failures)
	}
}

func TestSources_TheHolderNameIsAskedOncePerAS(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "asn,as_name")
	for _, a := range []string{"8.8.4.1", "8.8.4.2", "8.8.4.3", "8.8.4.4"} {
		w.ownedBy(a, 15169, "8.8.4.0/24", "GOOGLE")
	}
	for _, r := range w.lookup("8.8.4.1", "8.8.4.2", "8.8.4.3", "8.8.4.4") {
		if deref(r.Record.ASName) != "GOOGLE" {
			t.Errorf("%s as_name = %s", r.Record.Address, deref(r.Record.ASName))
		}
	}
	if n := w.dns.queried("AS15169.asn.cymru.com"); n != 1 {
		t.Errorf("the AS name was asked %d times, want 1", n)
	}
}

func TestSources_OneBootstrapForTheCall(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "rdap_org")
	w.http.on(bootstrapURL4, 200, bootstrapFile)
	var as []string
	for i := 1; i <= 6; i++ {
		a := fmt.Sprintf("8.8.4.%d", i)
		as = append(as, a)
		w.http.on(arinBase+"ip/"+a, 200, rdapAnswer("8.8.4.0", "8.8.4.255", "Google LLC"))
	}
	for _, r := range w.lookup(as...) {
		if deref(r.Record.RDAPOrg) != "Google LLC" {
			t.Errorf("%s rdap_org = %s", r.Record.Address, deref(r.Record.RDAPOrg))
		}
	}
	if n := w.http.count(bootstrapURL4); n != 1 {
		t.Errorf("the bootstrap was fetched %d times, want 1", n)
	}
}

func TestSources_RDAPReferralIsFollowed(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "rdap_netblock,rdap_org,rdap_registry")
	w.http.on(bootstrapURL4, 200, bootstrapFile)
	w.http.set(arinBase+"ip/8.8.4.4", fakeReply{status: 302, header: map[string][]string{"Location": {ripeBase + "ip/8.8.4.4"}}})
	w.http.on(ripeBase+"ip/8.8.4.4", 200, rdapAnswer("8.8.4.0", "8.8.4.127", "Moved"))
	r := only(t, w.lookup(pubAddr)).Record
	if deref(r.RDAPRegistry) != "ripe" || deref(r.RDAPNetblock) != "8.8.4.0/25" || deref(r.RDAPOrg) != "Moved" {
		t.Errorf("registration = %s %s %s", deref(r.RDAPRegistry), deref(r.RDAPNetblock), deref(r.RDAPOrg))
	}
}

func TestSources_RDAPNetblockThatIsNoSingleCIDR(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "rdap_netblock")
	w.http.on(bootstrapURL4, 200, bootstrapFile)
	w.http.on(arinBase+"ip/8.8.4.4", 200, rdapAnswer("8.8.4.0", "8.8.5.255", "X"))
	r := only(t, w.lookup(pubAddr)).Record
	if got := deref(r.RDAPNetblock); got != "8.8.4.0/23" {
		t.Errorf("netblock = %s", got)
	}
	w.http.on(arinBase+"ip/8.8.4.4", 200, rdapAnswer("8.8.4.0", "8.8.4.200", "X"))
	if got := deref(only(t, w.lookup(pubAddr)).Record.RDAPNetblock); got != "8.8.4.0-8.8.4.200" {
		t.Errorf("netblock = %s, want start-end", got)
	}
}

func TestSources_HackerTargetRules(t *testing.T) {
	t.Parallel()
	t.Run("IPv6 is not asked", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, false, "all")
		w.bootstrapped()
		w.ownedBy(pub6, 15169, "2001:4860::/32", "GOOGLE")
		res := only(t, w.lookup(pub6))
		if res.Record.ReverseIP != nil || res.Record.ReverseIPCount != nil || len(res.Record.Failures) != 0 {
			t.Errorf("record = %+v, want null reverse ip and no failure", res.Record)
		}
		if w.http.count("https://api.hackertarget.com") != 0 || slices.Contains(res.Asked, SourceHackerTarget) {
			t.Errorf("hackertarget was asked for an IPv6 address: %v", res.Asked)
		}
	})
	t.Run("shared is not asked", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, false, "all")
		w.bootstrapped()
		w.ownedBy("1.1.1.1", 13335, "1.1.1.0/24", "CLOUDFLARENET")
		res := only(t, w.lookup("1.1.1.1"))
		r := res.Record
		if r.ReverseIP != nil || r.ReverseIPCount != nil || len(r.Failures) != 0 || w.http.count("https://api.hackertarget.com") != 0 {
			t.Errorf("record = %+v, want null reverse ip and no failure, no request", r)
		}
		if deref(r.Provider) != "cloudflare" || deref(r.ProviderClass) != "cdn" {
			t.Errorf("provider = %s %s", deref(r.Provider), deref(r.ProviderClass))
		}
		if slices.Contains(res.Asked, SourceHackerTarget) {
			t.Errorf("asked = %v", res.Asked)
		}
	})
	t.Run("a hyperscaler is asked", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, false, "provider,provider_class,reverse_ip,reverse_ip_count")
		w.ownedBy("8.8.4.4", 16509, "8.8.4.0/24", "AMAZON-02")
		w.http.on(hackerTargetURL("8.8.4.4"), 200, "x.example.com\n")
		r := only(t, w.lookup("8.8.4.4")).Record
		if deref(r.Provider) != "aws" || deref(r.ProviderClass) != "hyperscaler" || !slices.Equal(r.ReverseIP, []string{"x.example.com"}) {
			t.Errorf("record = provider %s %s, reverse %v", deref(r.Provider), deref(r.ProviderClass), r.ReverseIP)
		}
	})
	t.Run("the first 100 and the count", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, false, "reverse_ip,reverse_ip_count")
		w.ownedBy(pubAddr, 15169, "8.8.4.0/24", "GOOGLE")
		var names []string
		for i := range 150 {
			names = append(names, fmt.Sprintf("h%03d.example.com", i))
		}
		slices.Reverse(names)
		w.http.on(hackerTargetURL(pubAddr), 200, strings.Join(names, "\n")+"\n"+names[0]+"\n")
		r := only(t, w.lookup(pubAddr)).Record
		if len(r.ReverseIP) != 100 || r.ReverseIP[0] != "h000.example.com" || r.ReverseIP[99] != "h099.example.com" || r.ReverseIPCount == nil || *r.ReverseIPCount != 150 {
			t.Errorf("reverse ip = %d names from %s, count %v; want 100 and 150", len(r.ReverseIP), r.ReverseIP[0], r.ReverseIPCount)
		}
	})
}

func TestHackerTargetApplies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		addr   string
		shared bool
		want   bool
	}{{"8.8.4.4", false, true}, {"8.8.4.4", true, false}, {"2001:4860::1", false, false}, {"2001:4860::1", true, false}} {
		if got := hackerTargetApplies(addr(tc.addr), tc.shared); got != tc.want {
			t.Errorf("hackerTargetApplies(%s, shared %v) = %v, want %v", tc.addr, tc.shared, got, tc.want)
		}
	}
}

func TestParseGeolocation(t *testing.T) {
	t.Parallel()
	loc := func(c, city string, pct float64) string {
		return fmt.Sprintf(`{"country":%q,"city":%q,"resources":["x"],"covered_percentage":%v}`, c, city, pct)
	}
	wrap := func(locs ...string) string {
		return `{"status":"ok","data":{"located_resources":[{"locations":[` + strings.Join(locs, ",") + `]}]}}`
	}
	cases := []struct {
		name          string
		body          string
		country, city string // "<null>" for null
	}{
		{"the largest cover wins", wrap(loc("AU", "Sydney", 30), loc("US", "Austin", 70)), "US", "Austin"},
		{"the largest cover wins whatever the order", wrap(loc("US", "Austin", 70), loc("AU", "Sydney", 30)), "US", "Austin"},
		{"a tie keeps the first", wrap(loc("AU", "Sydney", 50), loc("US", "Austin", 50)), "AU", "Sydney"},
		{"unknown country", wrap(loc("?", "", 100)), "<null>", "<null>"},
		{"empty country", wrap(loc("", "Nowhere", 100)), "<null>", "Nowhere"},
		{"empty city", wrap(loc("NZ", "", 100)), "NZ", "<null>"},
		{"no locations", wrap(), "<null>", "<null>"},
		{"no resources", `{"data":{"located_resources":[]}}`, "<null>", "<null>"},
		{"no data", `{}`, "<null>", "<null>"},
		{"empty body", ``, "<null>", "<null>"},
	}
	for _, tc := range cases {
		country, city, err := parseGeolocation([]byte(tc.body))
		if err != nil || deref(country) != tc.country || deref(city) != tc.city {
			t.Errorf("%s: %s %s %v, want %s %s", tc.name, deref(country), deref(city), err, tc.country, tc.city)
		}
	}
	for _, bad := range []string{`not json`, `{"data":`, `[1,2]`} {
		if _, _, err := parseGeolocation([]byte(bad)); err == nil {
			t.Errorf("parseGeolocation(%q) gave no error", bad)
		}
	}
}

func TestParseInternetDB(t *testing.T) {
	t.Parallel()
	got, err := parseInternetDB([]byte(`{"cpes":["b","a","a"],"hostnames":null,"ip":"1.2.3.4","ports":[443,80,443],"tags":[],"vulns":["CVE-2","CVE-10","CVE-1"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Ports, []int{80, 443}) || !slices.Equal(got.CPEs, []string{"a", "b"}) || !slices.Equal(got.Vulns, []string{"CVE-1", "CVE-10", "CVE-2"}) {
		t.Errorf("parsed = %+v", got)
	}
	if got.Hostnames == nil || got.Tags == nil || len(got.Hostnames)+len(got.Tags) != 0 {
		t.Errorf("empty lists are %#v and %#v, want [] not null", got.Hostnames, got.Tags)
	}
	empty, err := parseInternetDB([]byte(`{}`))
	if err != nil || empty.Ports == nil || empty.Vulns == nil {
		t.Errorf("{} = %+v, %v; want empty lists", empty, err)
	}
	for _, bad := range []string{`nope`, `{"ports":[`, `{"ports":"80"}`, `[]`} {
		if _, err := parseInternetDB([]byte(bad)); err == nil {
			t.Errorf("parseInternetDB(%q) gave no error", bad)
		}
	}
}

// --- Latches ---

func manyAddrs(n int) []string {
	var out []string
	for i := 1; i <= n; i++ {
		out = append(out, fmt.Sprintf("8.8.4.%d", i))
	}
	return out
}

func TestLatch_InternetDBAndRIPEstat(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		src    Source
		fields string
		url    func(string) string
		host   string
	}{
		{SourceInternetDB, "internetdb_ports", internetDBURL, "https://internetdb.shodan.io"},
		{SourceRIPEstat, "geo_country", ripestatURL, "https://stat.ripe.net"},
	} {
		t.Run(string(tc.src), func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, false, tc.fields)
			as := manyAddrs(5)
			for _, a := range as {
				w.http.set(tc.url(a), fakeReply{status: 429, body: "slow down", delay: 60 * time.Millisecond}) // the others queue behind it
			}
			res := w.lookup(as...)
			if n := w.http.count(tc.host); n != 1 {
				t.Errorf("%d requests reached %s, want 1", n, tc.host)
			}
			latched := 0
			for _, r := range res {
				f, ok := failureOf(r.Record, tc.src)
				if !ok || f.Code != clierr.RateLimited || !f.Transient || f.Quota {
					t.Errorf("%s failure = %+v (%v), want transient RATE_LIMITED", r.Record.Address, f, ok)
				}
				if f.Message == latchedMessage {
					latched++
				}
			}
			if latched != 4 {
				t.Errorf("%d addresses were not asked, want 4", latched)
			}
			if got := w.warnings(); len(got) != 1 {
				t.Errorf("warnings = %q, want exactly one", got)
			}
		})
	}
}

func TestLatch_ARegistryHostOnly(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "rdap_org")
	w.http.on(bootstrapURL4, 200, bootstrapFile)
	for _, a := range []string{"8.8.4.1", "8.8.4.2", "8.8.4.3"} {
		w.http.set(arinBase+"ip/"+a, fakeReply{status: 429, delay: 60 * time.Millisecond})
	}
	w.http.on(ripeBase+"ip/9.9.9.9", 200, rdapAnswer("9.9.9.0", "9.9.9.255", "Quad"))
	res := w.lookup("8.8.4.1", "8.8.4.2", "9.9.9.9", "8.8.4.3")
	if n := w.http.count("https://rdap.arin.net"); n != 1 {
		t.Errorf("%d requests reached the registry that limited the call, want 1", n)
	}
	if deref(res[2].Record.RDAPOrg) != "Quad" || len(res[2].Record.Failures) != 0 {
		t.Errorf("an address of another registry = %+v", res[2].Record)
	}
	latched := 0
	for _, i := range []int{0, 1, 3} {
		f, ok := failureOf(res[i].Record, SourceRDAP)
		if !ok || f.Code != clierr.RateLimited || !f.Transient {
			t.Errorf("%s failure = %+v (%v)", res[i].Record.Address, f, ok)
		}
		if f.Message == latchedMessage {
			latched++
		}
	}
	if latched != 2 {
		t.Errorf("%d addresses were not asked, want 2", latched)
	}
	if got := w.warnings(); len(got) != 1 || !strings.Contains(got[0], "rdap.arin.net") {
		t.Errorf("warnings = %q, want one naming the registry", got)
	}
}

func TestLatch_TheBootstrapHost(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "rdap_org")
	w.http.on(bootstrapURL4, 429, "")
	res := w.lookup(manyAddrs(4)...)
	if n := w.http.count("https://data.iana.org"); n != 1 {
		t.Errorf("%d bootstrap requests, want 1", n)
	}
	for _, r := range res {
		if f, ok := failureOf(r.Record, SourceRDAP); !ok || f.Code != clierr.RateLimited || !f.Transient {
			t.Errorf("%s failure = %+v (%v)", r.Record.Address, f, ok)
		}
	}
	if got := w.warnings(); len(got) != 1 {
		t.Errorf("warnings = %q, want one", got)
	}
}

func TestLatch_HackerTargetQuota(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		reply fakeReply
	}{
		{"text", fakeReply{status: 200, body: "API count exceeded - Increase Quota with Membership"}},
		{"429", fakeReply{status: 429}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, false, "reverse_ip")
			as := manyAddrs(4)
			for _, a := range as {
				w.ownedBy(a, 15169, "8.8.4.0/24", "GOOGLE")
				w.http.set(hackerTargetURL(a), tc.reply)
			}
			res := w.lookup(as...)
			if n := w.http.count("https://api.hackertarget.com"); n != 1 {
				t.Errorf("%d requests reached hackertarget, want 1", n)
			}
			for _, r := range res {
				f, ok := failureOf(r.Record, SourceHackerTarget)
				if !ok || f.Code != clierr.RateLimited || !f.Quota || f.Transient || f.Message == "" {
					t.Errorf("%s failure = %+v (%v), want a quota RATE_LIMITED that is not transient", r.Record.Address, f, ok)
				}
				if r.Record.ReverseIP != nil || r.Record.ReverseIPCount != nil {
					t.Errorf("%s has reverse ip data", r.Record.Address)
				}
			}
			got := w.warnings()
			if len(got) != 1 || !strings.Contains(got[0], "quota resets daily") {
				t.Errorf("warnings = %q, want one saying the quota resets daily", got)
			}
		})
	}
}

// --- Fields ---

func TestFields_OnlyTheNeededSourcesAreAsked(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		fields   string
		wantDNS  []string
		wantHTTP []string
	}{
		{"asn", []string{originName(pubAddr) + "/16", "AS15169.asn.cymru.com/16"}, nil},
		{"as_prefix", []string{originName(pubAddr) + "/16", "AS15169.asn.cymru.com/16"}, nil},
		{"reverse_ip", []string{originName(pubAddr) + "/16", "AS15169.asn.cymru.com/16"}, []string{"https://api.hackertarget.com"}},
		{"ptr", []string{ptrName(pubAddr) + "/12"}, nil},
		{"geo_city", nil, []string{"https://stat.ripe.net"}},
		{"internetdb_tags", nil, []string{"https://internetdb.shodan.io"}},
		{"", nil, nil},
	} {
		t.Run("fields="+tc.fields, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, false, tc.fields)
			w.populate(pubAddr)
			res := only(t, w.lookup(pubAddr))
			got := w.dns.queries()
			slices.Sort(got)
			want := slices.Clone(tc.wantDNS)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("DNS queries = %v, want %v", got, want)
			}
			for _, p := range []string{"https://api.hackertarget.com", "https://stat.ripe.net", "https://internetdb.shodan.io", "https://data.iana.org", "https://rdap."} {
				if (w.http.count(p) > 0) != slices.Contains(tc.wantHTTP, p) {
					t.Errorf("requests to %s = %d, want asked %v", p, w.http.count(p), slices.Contains(tc.wantHTTP, p))
				}
			}
			if !slices.Equal(res.Asked, w.cfg.Fields.Sources()) && tc.fields != "reverse_ip" {
				t.Errorf("asked = %v, want %v", res.Asked, w.cfg.Fields.Sources())
			}
		})
	}
}

// --- Non-public addresses ---

var nonPublic = map[string]addrkind.Kind{
	"10.0.0.1": "private", "100.64.0.1": "cgnat", "fd00::1": "ula", "169.254.1.1": "link-local", "192.0.2.1": "documentation",
	"224.0.0.1": "multicast", "255.255.255.255": "broadcast", "0.0.0.0": "unspecified", "2002::1": "6to4", "2001::1": "teredo",
	"127.0.0.1": "loopback",
}

func TestNonPublic_NothingIsSentOffTheMachine(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	var as []string
	for a := range nonPublic {
		as = append(as, a)
	}
	slices.Sort(as)
	for _, res := range w.lookup(as...) {
		r := res.Record
		if r.Kind != nonPublic[r.Address] || len(r.Failures) != 0 || r.Hostnames == nil {
			t.Errorf("%s = %+v", r.Address, r)
		}
		if r.ASN != nil || r.ASName != nil || r.ASPrefix != nil || r.RDAPNetblock != nil || r.RDAPOrg != nil || r.RDAPRegistry != nil ||
			r.Provider != nil || r.ProviderClass != nil || r.GeoCountry != nil || r.GeoCity != nil || r.ReverseIPCount != nil {
			t.Errorf("%s has a value for a single key: %+v", r.Address, r)
		}
		for name, l := range map[string]int{
			"ptr": len(r.PTR), "ports": len(r.InternetDBPorts), "hostnames": len(r.InternetDBHostnames), "tags": len(r.InternetDBTags),
			"cpes": len(r.InternetDBCPEs), "vulns": len(r.InternetDBVulns), "reverse": len(r.ReverseIP),
		} {
			if l != 0 {
				t.Errorf("%s %s has entries", r.Address, name)
			}
		}
		if r.PTR == nil || r.InternetDBPorts == nil || r.InternetDBHostnames == nil || r.InternetDBTags == nil || r.InternetDBCPEs == nil || r.InternetDBVulns == nil || r.ReverseIP == nil {
			t.Errorf("%s: a list is null, want []", r.Address)
		}
	}
	if q := w.dns.queries(); len(q) != 0 {
		t.Errorf("public resolvers were asked: %v", q)
	}
	if w.http.total() != 0 {
		t.Errorf("a third party was asked: %v", w.http.asked)
	}
	if w.local.asked() != nil {
		t.Errorf("the local resolver was asked without --active: %v", w.local.asked())
	}
}

func TestNonPublic_ActiveAsksOnlyTheLocalResolverForThePTR(t *testing.T) {
	t.Parallel()
	w := newWorld(t, true, "ptr,not_contacted")
	w.local.ptrs["10.0.0.1"] = []string{"host.corp.example", "host.corp.example"}
	w.local.errs["ptr:10.0.0.2"] = fmt.Errorf("%w: slow", egress.ErrLocalTimeout)
	w.local.errs["ptr:10.0.0.3"] = errors.New("server misbehaving")
	res := w.lookup("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4")
	if !slices.Equal(res[0].Record.PTR, []string{"host.corp.example"}) {
		t.Errorf("10.0.0.1 ptr = %v", res[0].Record.PTR)
	}
	if res[3].Record.PTR == nil || len(res[3].Record.PTR) != 0 || len(res[3].Record.Failures) != 0 {
		t.Errorf("10.0.0.4 = %+v, want an empty answer", res[3].Record)
	}
	for i, code := range map[int]clierr.Code{1: clierr.Timeout, 2: clierr.NetworkError} {
		f, ok := failureOf(res[i].Record, SourcePTR)
		if !ok || f.Code != code || !f.Transient || res[i].Record.PTR != nil {
			t.Errorf("%s ptr = %v, failure %+v (%v), want transient %s", res[i].Record.Address, res[i].Record.PTR, f, ok, code)
		}
	}
	if q := w.dns.queries(); len(q) != 0 {
		t.Errorf("public resolvers were asked: %v", q)
	}
	if w.http.total() != 0 {
		t.Errorf("a third party was asked: %v", w.http.asked)
	}
	if got := len(w.local.asked()); got != 4 {
		t.Errorf("the local resolver was asked %d times, want 4: %v", got, w.local.asked())
	}
}

func TestNonPublic_ActiveWithoutPTRSelectedAsksNothing(t *testing.T) {
	t.Parallel()
	w := newWorld(t, true, "not_contacted")
	w.lookup("0.0.0.0")
	if w.local.asked() != nil {
		t.Errorf("local asked %v", w.local.asked())
	}
}

func TestPublicAddressesAndNonPublicOnesTogether(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	w.populate(pubAddr)
	res := w.lookup("10.0.0.1", pubAddr, "2002::1")
	if res[1].Record.ASN == nil || res[0].Record.Kind != "private" || res[2].Record.Kind != "6to4" {
		t.Errorf("results = %+v", res)
	}
	for _, q := range w.dns.queries() {
		if strings.Contains(q, "10.0.0.1") || strings.HasPrefix(q, "1.0.0.10.") || strings.Contains(q, "2.0.0.2") {
			t.Errorf("the public resolvers saw a non-public address: %s", q)
		}
	}
}
