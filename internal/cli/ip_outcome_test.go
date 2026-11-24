package cli_test

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/cli"
)

// Outcome tests cover pacing, refusal latches, deadlines, retry hints, human layout and help
// using ipWorld.

// updateIP rewrites the files under testdata/ip instead of comparing with them:
//
//	go test ./internal/cli/ -run 'TestIPRender_' -update-ip
var updateIP = flag.Bool("update-ip", false, "rewrite the files under testdata/ip instead of comparing with them")

// ---- helpers ----

// ipoRun runs nyx ip in the mode.
func ipoRun(w *ipWorld, jsonMode bool, args ...string) int {
	w.t.Helper()
	if jsonMode {
		return w.runJSON(args...)
	}
	return w.run(args...)
}

// ipoPartial runs nyx ip, requires exit 7 with a PARTIAL error, and returns the error.
func ipoPartial(w *ipWorld, jsonMode bool, args ...string) failure {
	w.t.Helper()
	if code := ipoRun(w, jsonMode, args...); code != 7 {
		w.t.Fatalf("nyx ip %v (json=%v): exit %d, want 7\nstdout %q\nstderr %q", args, jsonMode, code, w.h.stdout.String(), w.h.stderr.String())
	}
	f := w.h.theError(jsonMode)
	if f.code != "PARTIAL" {
		w.t.Errorf("nyx ip %v (json=%v): code %s, want PARTIAL: %+v", args, jsonMode, f.code, f)
	}
	return f
}

// ipoRetry parses hint inputs and flags, sorting flags so tests do not depend on their output
// order.
func ipoRetry(t *testing.T, hint string) (inputs, flags []string) {
	t.Helper()
	_, cmd, ok := strings.Cut(hint, "run: ")
	if !ok {
		t.Fatalf("the hint %q does not say what to run", hint)
	}
	f := strings.Fields(cmd)
	if len(f) < 2 || f[0] != "nyx" || f[1] != "ip" {
		t.Fatalf("the hint %q is not a nyx ip command", hint)
	}
	f = f[2:]
	i := 0
	for i < len(f) && !strings.HasPrefix(f[i], "-") {
		i++
	}
	flags = slices.Clone(f[i:])
	slices.Sort(flags)
	return f[:i], flags
}

// ipoFailuresOf filters record failures to one source.
func ipoFailuresOf(r ipRecord, source string) []ipFailure {
	var out []ipFailure
	for _, f := range r.failures() {
		if f.Source == source {
			out = append(out, f)
		}
	}
	return out
}

// ipoIDBBody is InternetDB's answer for an address with the open ports.
func ipoIDBBody(addr string, ports ...int) string {
	l := make([]string, len(ports))
	for i, p := range ports {
		l[i] = fmt.Sprint(p)
	}
	return fmt.Sprintf(`{"cpes":[],"hostnames":[],"ip":%q,"ports":[%s],"tags":[],"vulns":[]}`, addr, strings.Join(l, ","))
}

// ipoPath is the last part of a request's path: the address InternetDB is asked about.
func ipoPath(r *http.Request) string { return strings.TrimPrefix(r.URL.Path, "/") }

// ipoExceeded is HackerTarget's reply to a lookup that is over the day's allowance.
const ipoExceeded = "API count exceeded - Increase Quota with Membership"

// ipoNotAsked builds the expected explanation for a request suppressed after source refusal.
const ipoNotAsked = "not asked: rate-limited earlier in this call"

// ipoStamps is a source's handler that records when each request arrived, and answers it.
type ipoStamps struct {
	mu    sync.Mutex
	times []time.Time
	reply func(r *http.Request) string
}

func (s *ipoStamps) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.times = append(s.times, time.Now())
		s.mu.Unlock()
		ipReply(200, s.reply(r))(rw, r)
	}
}

// gaps are the times between one request's arrival and the next's.
func (s *ipoStamps) gaps() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := slices.Clone(s.times)
	slices.SortFunc(ts, func(a, b time.Time) int { return a.Compare(b) })
	var out []time.Duration
	for i := 1; i < len(ts); i++ {
		out = append(out, ts[i].Sub(ts[i-1]))
	}
	return out
}

// ipoClosedExcept refuses all probe ports except those selected for the test.
func ipoClosedExcept(w *ipWorld, addr string, keep ...int) {
	w.t.Helper()
	for _, p := range ipProbePorts {
		if !slices.Contains(keep, p) {
			w.closedPort(addr, p)
		}
	}
}

// ---- time: paces, latches and the deadline ----

// An InternetDB 429 suppresses later requests to that source only and produces one warning plus
// per-address transient failures.
func TestIPTime_InternetDBRateLimitLatchesForTheRestOfTheCall(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.eopts.SourceRates[ipHostInternetDB] = 5 // so the answer of the third request is known before the fourth is made
	addrs := []string{"8.8.4.1", "8.8.4.2", "8.8.4.3", "8.8.4.4", "8.8.4.5", "8.8.4.6"}
	var requests atomic.Int32
	w.idb.setAll(func(rw http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 3 {
			ipStatus(http.StatusTooManyRequests)(rw, r)
			return
		}
		ipReply(200, ipoIDBBody(ipoPath(r), 443))(rw, r)
	})
	env, f := w.partial(addrs...)
	if got := w.idb.count(); got != 3 {
		t.Errorf("InternetDB was asked %d times, want the 3 requests up to its 429", got)
	}
	if got := w.geo.count(); got != len(addrs) {
		t.Errorf("RIPEstat was asked %d times, want %d: only InternetDB is latched", got, len(addrs))
	}
	if !f.transient {
		t.Errorf("error %+v is not transient", f)
	}
	var answered, limited, notAsked int
	for _, r := range env.Records {
		fs := ipoFailuresOf(r, "internetdb")
		if len(fs) == 0 {
			answered++
			if got := r.list("internetdb_ports"); len(got) != 1 {
				t.Errorf("%s: internetdb_ports = %v", r.address(), r.m["internetdb_ports"])
			}
			continue
		}
		if len(fs) != 1 || fs[0].Code != "RATE_LIMITED" || !fs[0].Transient || fs[0].Quota {
			t.Errorf("%s: failures %+v, want one transient RATE_LIMITED that is not a quota", r.address(), fs)
		}
		if strings.Contains(fs[0].Message, ipoNotAsked) {
			notAsked++
		} else {
			limited++
		}
		for _, k := range []string{"internetdb_ports", "internetdb_hostnames", "internetdb_tags", "internetdb_cpes", "internetdb_vulns"} {
			if !r.isNull(k) {
				t.Errorf("%s: %s = %v, want null", r.address(), k, r.m[k])
			}
		}
		if len(ipoFailuresOf(r, "ripestat")) != 0 {
			t.Errorf("%s: a source that was not limited is affected: %s", r.address(), r.raw)
		}
	}
	if len(env.Records) != len(addrs) || answered != 2 || limited != 1 || notAsked != 3 {
		t.Errorf("%d records: %d answered, %d told 429, %d not asked; want 6, 2, 1, 3", len(env.Records), answered, limited, notAsked)
	}
	if len(env.Meta.Warnings) != 1 || !strings.Contains(strings.ToLower(env.Meta.Warnings[0]), "internetdb") {
		t.Errorf("warnings %q, want one that names InternetDB", env.Meta.Warnings)
	}
}

// A 429 from one RDAP registry host latches that host only: an address held by another registry is
// still asked.
func TestIPTime_RDAPRateLimitLatchesThatRegistryOnly(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.eopts.SourceRates[hostARIN] = 5
	w.route("193.0.0.0/8", hostRIPE)
	w.netblock(hostRIPE, "193.0.0.0", "193.0.0.255", "NET-RIPE", "RIPE Example Org")
	w.rdap[hostARIN].setAll(ipStatus(http.StatusTooManyRequests))
	env, _ := w.partial("8.8.4.1", "8.8.4.2", "8.8.4.3", "193.0.0.1")
	if got := w.rdap[hostARIN].count(); got != 1 {
		t.Errorf("ARIN was asked %d times, want only the request it refused", got)
	}
	if got := w.rdap[hostRIPE].countFor("193.0.0.1"); got != 1 {
		t.Errorf("RIPE was asked %d times about 193.0.0.1, want 1", got)
	}
	var limited, notAsked int
	for _, r := range env.Records {
		fs := ipoFailuresOf(r, "rdap")
		if r.address() == "193.0.0.1" {
			if len(fs) != 0 || r.str("rdap_org") != "RIPE Example Org" {
				t.Errorf("193.0.0.1: %s", r.raw)
			}
			continue
		}
		if len(fs) != 1 || fs[0].Code != "RATE_LIMITED" || !fs[0].Transient || fs[0].Quota || !r.isNull("rdap_org") {
			t.Errorf("%s: %s", r.address(), r.raw)
			continue
		}
		if strings.Contains(fs[0].Message, ipoNotAsked) {
			notAsked++
		} else {
			limited++
		}
	}
	if len(env.Records) != 4 || limited != 1 || notAsked != 2 {
		t.Errorf("%d records, %d told 429, %d not asked; want 4, 1, 2", len(env.Records), limited, notAsked)
	}
	if len(env.Meta.Warnings) != 1 || !strings.Contains(strings.ToLower(env.Meta.Warnings[0]), "rdap") || strings.Contains(strings.ToLower(env.Meta.Warnings[0]), "ripe") {
		t.Errorf("warnings %q, want one about the latched registry only", env.Meta.Warnings)
	}
}

// HackerTarget quota exhaustion stops later calls and warns once. Quota failures remain visible
// but do not fail the batch or suggest immediate retry.
func TestIPTime_HackerTargetQuotaLatches(t *testing.T) {
	t.Parallel()
	for _, reply := range []struct {
		name string
		h    http.HandlerFunc
	}{{"API count exceeded reply", ipReply(200, ipoExceeded)}, {"429", ipStatus(http.StatusTooManyRequests)}} {
		for _, answeredFirst := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s after %d answers", reply.name, answeredFirst), func(t *testing.T) {
				t.Parallel()
				w := newIPWorld(t)
				w.h.eopts.SourceRates[ipHostHackerTarget] = 5
				var requests atomic.Int32
				w.ht.setAll(func(rw http.ResponseWriter, r *http.Request) {
					if int(requests.Add(1)) <= answeredFirst {
						ipReply(200, "x.example.org\ny.example.org")(rw, r)
						return
					}
					reply.h(rw, r)
				})
				env := w.lookup("8.8.4.1", "8.8.4.2", "8.8.4.3", "8.8.4.4")
				if got := w.ht.count(); got != answeredFirst+1 {
					t.Errorf("HackerTarget was asked %d times, want %d: not again once the quota is spent", got, answeredFirst+1)
				}
				names, quota := ipoCountQuota(t, env.Records)
				if names != answeredFirst || quota != 4-answeredFirst {
					t.Errorf("%d records with names, %d with a quota failure; want %d and %d", names, quota, answeredFirst, 4-answeredFirst)
				}
				if len(env.Meta.Warnings) != 1 || !strings.Contains(env.Meta.Warnings[0], "resets daily") {
					t.Errorf("warnings %q, want one that says the quota resets daily", env.Meta.Warnings)
				}
				if len(env.Meta.Errors) != 0 {
					t.Errorf("meta.errors %+v", env.Meta.Errors)
				}
			})
		}
	}
}

// ipoCountQuota requires every record to contain either reverse names or a quota failure.
func ipoCountQuota(t *testing.T, records []ipRecord) (names, quota int) {
	t.Helper()
	for _, r := range records {
		fs := ipoFailuresOf(r, "hackertarget")
		if len(fs) == 0 {
			names++
			if !slices.Equal(r.strs("reverse_ip"), []string{"x.example.org", "y.example.org"}) {
				t.Errorf("%s: %s", r.address(), r.raw)
			}
			continue
		}
		quota++
		if len(fs) != 1 || fs[0].Code != "RATE_LIMITED" || !fs[0].Quota || fs[0].Transient {
			t.Errorf("%s: failures %+v, want one RATE_LIMITED quota failure that is not transient", r.address(), fs)
		}
		if !r.isNull("reverse_ip") || !r.isNull("reverse_ip_count") {
			t.Errorf("%s: reverse_ip %v, reverse_ip_count %v, want null", r.address(), r.m["reverse_ip"], r.m["reverse_ip_count"])
		}
	}
	return names, quota
}

// Default batch pacing separates InternetDB starts by one second and RIPEstat starts by a
// quarter second.
func TestIPTime_SourcesAreSlowedToTheirPaces(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		field  string
		min    time.Duration // the least gap between two requests, a little under the pace
		source func(w *ipWorld) *ipSource
		body   func(r *http.Request) string
	}{
		{"InternetDB, 1 a second", "internetdb_ports", 800 * time.Millisecond, func(w *ipWorld) *ipSource { return w.idb },
			func(r *http.Request) string { return ipoIDBBody(ipoPath(r)) }},
		{"RIPEstat, 4 a second", "geo_country", 200 * time.Millisecond, func(w *ipWorld) *ipSource { return w.geo },
			func(r *http.Request) string { return ipGeoBody(r.URL.Query().Get("resource"), nil) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			w.h.eopts.SourceRates = nil // the harness's fast paces are for the other tests
			stamps := &ipoStamps{reply: c.body}
			c.source(w).setAll(stamps.handler())
			w.lookup("8.8.4.1", "8.8.4.2", "8.8.4.3", "--fields", c.field)
			gaps := stamps.gaps()
			if len(gaps) != 2 {
				t.Fatalf("%d requests arrived, want 3", len(gaps)+1)
			}
			for _, g := range gaps {
				if g < c.min {
					t.Errorf("two requests arrived %v apart, want at least %v", g, c.min)
				}
			}
		})
	}
}

// Deadline expiry marks unanswered sources timed out while preserving completed data from other
// addresses/sources.
func TestIPTime_ASourceThatHangsPastTheTimeoutIsATimedOutFailure(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		w.h.eopts.HTTPTimeout = time.Minute // only the call's deadline may end the wait
		for _, a := range []string{"8.8.4.1", "8.8.4.2", "8.8.4.3"} {
			w.seed(a)
		}
		w.idb.set("8.8.4.2", ipHang())
		start := time.Now()
		code := ipoRun(w, jsonMode, "8.8.4.1", "8.8.4.2", "8.8.4.3", "--timeout", "2s")
		elapsed := time.Since(start)
		if code != 7 {
			t.Fatalf("json=%v: exit %d\nstderr %s", jsonMode, code, w.h.stderr.String())
		}
		if elapsed < 1800*time.Millisecond || elapsed > 6*time.Second {
			t.Errorf("json=%v: the call took %v, want about the 2s deadline", jsonMode, elapsed)
		}
		if !jsonMode {
			continue
		}
		env := w.h.ipEnvelope()
		for _, r := range env.Records {
			fs := ipoFailuresOf(r, "internetdb")
			if r.address() != "8.8.4.2" {
				if len(r.failures()) != 0 {
					t.Errorf("%s: failures %+v", r.address(), r.failures())
				}
				continue
			}
			if len(fs) != 1 || fs[0].Code != "TIMEOUT" || !fs[0].Transient || !r.isNull("internetdb_ports") || r.isNull("asn") {
				t.Errorf("8.8.4.2: %s", r.raw)
			}
		}
		if len(env.Records) != 3 {
			t.Errorf("%d records, want 3", len(env.Records))
		}
	}
}

// With no --timeout, the deadline for one address in the default mode is six seconds.
func TestIPTime_TheDefaultDeadlineForOneAddressIsSixSeconds(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.eopts.HTTPTimeout = time.Minute
	w.idb.setAll(ipHang())
	start := time.Now()
	env, _ := w.partial("8.8.4.4")
	if el := time.Since(start); el < 5500*time.Millisecond || el > 9*time.Second {
		t.Errorf("the call took %v, want about 6s", el)
	}
	if f := env.Records[0].failureOf("internetdb"); f.Code != "TIMEOUT" || !f.Transient {
		t.Errorf("failure %+v", f)
	}
}

// ---- outcome: the exit code and the hint ----

// A call in which every input succeeds exits 0 with nothing on stderr, in either mode.
func TestIPOutcome_EveryInputSucceedingExitsZero(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		w.dns.A("web.example.com", "1.1.1.1")
		w.seed("8.8.4.4")
		w.seed("1.1.1.1")
		if code := ipoRun(w, jsonMode, "8.8.4.4", "web.example.com", "10.0.0.1"); code != 0 {
			t.Fatalf("json=%v: exit %d\nstderr %s", jsonMode, code, w.h.stderr.String())
		}
		if w.h.stderr.Len() != 0 {
			t.Errorf("json=%v: stderr %q", jsonMode, w.h.stderr.String())
		}
		if jsonMode {
			if env := w.h.ipEnvelope(); len(env.Records) != 3 || len(env.Meta.Errors) != 0 {
				t.Errorf("envelope %s", w.h.stdout.String())
			}
		}
	}
}

// HackerTarget quota-only failures remain in records/warnings while the command succeeds,
// including with a minimal source selection.
func TestIPOutcome_QuotaFailuresAloneExitZero(t *testing.T) { // mutation target
	t.Parallel()
	for _, c := range []struct {
		name  string
		reply http.HandlerFunc
		args  []string
	}{
		{"exceeded reply", ipReply(200, ipoExceeded), nil},
		{"429", ipStatus(http.StatusTooManyRequests), nil},
		{"only reverse_ip selected", ipReply(200, ipoExceeded), []string{"--fields", "reverse_ip"}},
	} {
		for _, jsonMode := range modes {
			w := newIPWorld(t)
			w.seed("8.8.4.4")
			w.seed("8.8.4.5")
			w.ht.setAll(c.reply)
			args := append([]string{"8.8.4.4", "8.8.4.5"}, c.args...)
			if code := ipoRun(w, jsonMode, args...); code != 0 {
				t.Fatalf("%s (json=%v): exit %d, want 0: a spent quota is not a failure of the call\nstdout %q\nstderr %q", c.name, jsonMode, code, w.h.stdout.String(), w.h.stderr.String())
			}
			if strings.Contains(w.h.stderr.String(), "error:") || strings.Contains(w.h.stderr.String(), `"error"`) || strings.Contains(w.h.stdout.String(), "error:") {
				t.Errorf("%s (json=%v): an error was written\nstdout %q\nstderr %q", c.name, jsonMode, w.h.stdout.String(), w.h.stderr.String())
			}
			if jsonMode {
				env := w.h.ipEnvelope()
				if len(env.Records) != 2 || len(env.Meta.Errors) != 0 || len(env.Meta.Warnings) != 1 {
					t.Errorf("%s: %d records, meta %+v", c.name, len(env.Records), env.Meta)
				}
				for _, r := range env.Records {
					if f := r.failureOf("hackertarget"); !f.Quota || f.Transient || f.Code != "RATE_LIMITED" {
						t.Errorf("%s: %s", c.name, r.raw)
					}
				}
			} else if warns := w.h.logMsgs("WARN"); len(warns) != 1 || !strings.Contains(warns[0], "resets daily") {
				t.Errorf("%s: WARN lines %q", c.name, warns)
			}
		}
	}
}

// Partial retry hints preserve flags and name failed addresses directly rather than their
// CIDR/hostname inputs.
func TestIPOutcome_PartialHintRetriesTheFailingAddressesWithTheFlagsGiven(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		flags []string
		want  []string // the flags the hint repeats, besides --json
	}{
		{"default fields", []string{"--timeout", "30s"}, []string{"--timeout", "30s"}},
		{"every flag", []string{"--active", "--fields", "internetdb_ports", "--timeout", "30s"}, []string{"--active", "--fields", "internetdb_ports", "--timeout", "30s"}},
	} {
		for _, jsonMode := range modes {
			w := newIPWorld(t)
			w.dns.A("web.example.com", "9.9.9.9")
			w.sealProbes([]string{"8.8.4.0", "8.8.4.1", "8.8.4.2", "8.8.4.3", "9.9.9.9"})
			w.idb.set("8.8.4.2", ipStatus(500))
			w.idb.set("9.9.9.9", ipStatus(500))
			f := ipoPartial(w, jsonMode, append([]string{"8.8.4.0/30", "web.example.com"}, c.flags...)...)
			inputs, flags := ipoRetry(t, f.hint)
			want := slices.Clone(c.want)
			if jsonMode {
				want = append(want, "--json")
			}
			slices.Sort(want)
			if !slices.Equal(inputs, []string{"8.8.4.2", "9.9.9.9"}) || !slices.Equal(flags, want) {
				t.Errorf("%s (json=%v): hint %q, want the command for 8.8.4.2 and 9.9.9.9 with %v", c.name, jsonMode, f.hint, want)
			}
			if !f.transient {
				t.Errorf("%s (json=%v): %+v is not transient", c.name, jsonMode, f)
			}
			if got := w.contacted(); len(got) != 0 {
				t.Errorf("%s (json=%v): connections to %v", c.name, jsonMode, got)
			}
		}
	}
}

// Retry hints omit quota-only failures and retain independently retryable failures.
func TestIPOutcome_PartialHintLeavesOutQuotaFailures(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		w.ht.setAll(ipReply(200, ipoExceeded))
		w.idb.set("8.8.4.2", ipStatus(500))
		f := ipoPartial(w, jsonMode, "8.8.4.0/30")
		inputs, _ := ipoRetry(t, f.hint)
		if !slices.Equal(inputs, []string{"8.8.4.2"}) || !f.transient {
			t.Errorf("json=%v: %+v, want the hint to name 8.8.4.2 only", jsonMode, f)
		}
	}
}

// Without local-only fields, all-source failure yields no record and uses the first source's
// code. Separate tests cover local snapshot evidence preserving records.
func TestIPOutcome_NoSourceAnsweringIsTheCodeOfTheFirstFailingSource(t *testing.T) {
	t.Parallel()
	const addr = "8.8.4.4"
	servfail := int(mdns.RcodeServerFailure)
	for _, c := range []struct {
		name   string
		fields string // "" for every field
		want   string
		break_ func(w *ipWorld)
	}{
		{"every source, Team Cymru first", "asn,rdap_org,ptr,geo_country,internetdb_ports,reverse_ip", "NETWORK_ERROR", func(w *ipWorld) {
			w.dns.Rcode(cymruOriginName(addr), servfail)
			w.rdap[hostARIN].setAll(ipStatus(500))
			w.dns.Rcode(reverseName(addr), servfail)
			w.geo.setAll(ipStatus(500))
			w.idb.setAll(ipStatus(500))
			w.ht.setAll(ipStatus(500))
		}},
		{"RDAP before PTR, RIPEstat and InternetDB", "rdap_org,ptr,geo_country,internetdb_ports", "UPSTREAM_ERROR", func(w *ipWorld) {
			w.rdap[hostARIN].setAll(ipStatus(500))
			w.dns.Rcode(reverseName(addr), servfail)
			w.geo.setAll(ipStatus(429))
			w.idb.setAll(ipStatus(500))
		}},
		{"PTR before RIPEstat and InternetDB", "ptr,geo_country,internetdb_ports", "NETWORK_ERROR", func(w *ipWorld) {
			w.dns.Rcode(reverseName(addr), servfail)
			w.geo.setAll(ipStatus(500))
			w.idb.setAll(ipStatus(429))
		}},
		{"RIPEstat before InternetDB", "geo_country,internetdb_ports", "RATE_LIMITED", func(w *ipWorld) {
			w.geo.setAll(ipStatus(429))
			w.idb.setAll(ipStatus(500))
		}},
		{"InternetDB alone", "internetdb_ports", "UPSTREAM_ERROR", func(w *ipWorld) { w.idb.setAll(ipStatus(500)) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			for _, jsonMode := range modes {
				w := newIPWorld(t)
				w.seed(addr)
				c.break_(w)
				args := []string{addr}
				if c.fields != "" {
					args = append(args, "--fields", c.fields)
				}
				f := w.h.failed(ipoRun(w, jsonMode, args...), 1, jsonMode)
				if f.code != c.want || !f.transient {
					t.Errorf("json=%v: %+v, want a transient %s", jsonMode, f, c.want)
				}
			}
		})
	}
}

// Uniform failures retain NOT_FOUND/INVALID_INPUT status; mixed failure codes yield partial
// output conventions even with no records.
func TestIPOutcome_NoRecordTakesTheExitCodeOfTheOneCode(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		f := w.h.failed(ipoRun(w, jsonMode, "nx1.example.com", "nx2.example.com"), 3, jsonMode)
		if f.code != "NOT_FOUND" || f.transient {
			t.Errorf("json=%v: %+v", jsonMode, f)
		}

		w = newIPWorld(t)
		invalid := []string{"https://example.com/x", "8.8.4.4:80", "1234"}
		f = w.h.failed(ipoRun(w, jsonMode, invalid...), 2, jsonMode)
		if f.code != "INVALID_INPUT" || jsonMode && !slices.Equal(f.inputOf("input"), invalid) {
			t.Errorf("json=%v: %+v, want every invalid input listed", jsonMode, f)
		}
		if w.httpRequests() != 0 || w.dns.Total() != 0 {
			t.Errorf("json=%v: something was asked", jsonMode)
		}
	}
}

// Mixed-code failures retry transient addresses while excluding nonexistent names.
func TestIPOutcome_MixedCodesWithNoRecordExitSeven(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		f := ipoPartial(w, jsonMode, "https://example.com/x", "nx.example.com")
		if f.transient {
			t.Errorf("json=%v: %+v is transient, but nothing in it is worth retrying", jsonMode, f)
		}
		if jsonMode {
			env := w.h.ipEnvelope()
			codes := []string{}
			for _, e := range env.Meta.Errors {
				codes = append(codes, e.Code)
			}
			slices.Sort(codes)
			if len(env.Records) != 0 || !slices.Equal(codes, []string{"INVALID_INPUT", "NOT_FOUND"}) {
				t.Errorf("envelope %s", w.h.stdout.String())
			}
		} else if w.h.stdout.Len() != 0 {
			t.Errorf("stdout %q", w.h.stdout.String())
		}

		w = newIPWorld(t)
		w.idb.setAll(ipStatus(500))
		f = ipoPartial(w, jsonMode, "nx.example.com", "8.8.4.4", "--fields", "internetdb_ports")
		inputs, _ := ipoRetry(t, f.hint)
		if !slices.Equal(inputs, []string{"8.8.4.4"}) || !f.transient {
			t.Errorf("json=%v: %+v, want a transient error whose hint retries 8.8.4.4 only", jsonMode, f)
		}
	}
}

// Past twenty failures the hint does not list them: it points at meta.errors.
func TestIPOutcome_MoreThanTwentyFailuresPointAtTheErrors(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		w.idb.setAll(func(rw http.ResponseWriter, r *http.Request) {
			if ipoPath(r) == "8.8.8.8" {
				ipReply(200, ipoIDBBody("8.8.8.8", 443))(rw, r)
				return
			}
			ipStatus(500)(rw, r)
		})
		f := ipoPartial(w, jsonMode, "8.8.4.0/27", "8.8.8.8", "--fields", "internetdb_ports")
		if !strings.Contains(f.hint, "meta.errors") || strings.Contains(f.hint, "run:") || strings.Contains(f.hint, "8.8.4.") || !f.transient {
			t.Errorf("json=%v: %+v, want a transient error whose hint points at meta.errors", jsonMode, f)
		}
		if jsonMode {
			env := w.h.ipEnvelope()
			if len(env.Records) != 1 || len(env.Meta.Errors) != 32 {
				t.Errorf("%d records and %d errors, want 1 and 32", len(env.Records), len(env.Meta.Errors))
			}
		}
	}
}

// Local PTR failure stays visible on a successful non-public record without marking its input
// failed.
func TestIPOutcome_ANonPublicAddressWhoseLocalPTRFailsIsStillASuccess(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		w.local.Rcode(reverseName("10.0.0.1"), int(mdns.RcodeServerFailure))
		w.sealProbes([]string{"10.0.0.1"})
		if code := ipoRun(w, jsonMode, "10.0.0.1", "--active", "--fields", "ptr"); code != 0 {
			t.Fatalf("json=%v: exit %d\nstdout %q\nstderr %q", jsonMode, code, w.h.stdout.String(), w.h.stderr.String())
		}
		if !jsonMode {
			if strings.Contains(w.h.stderr.String(), "error:") || !strings.Contains(w.h.stdout.String(), "10.0.0.1") {
				t.Errorf("stdout %q\nstderr %q", w.h.stdout.String(), w.h.stderr.String())
			}
			continue
		}
		env := w.h.ipEnvelope()
		if len(env.Records) != 1 || len(env.Meta.Errors) != 0 || w.h.stderr.Len() != 0 {
			t.Fatalf("envelope %s\nstderr %q", w.h.stdout.String(), w.h.stderr.String())
		}
		r := env.Records[0]
		if f := r.failureOf("ptr"); !f.Transient || f.Quota || f.Message == "" || (f.Code != "NETWORK_ERROR" && f.Code != "TIMEOUT") || !r.isNull("ptr") || r.str("kind") != "private" {
			t.Errorf("record %s", r.raw)
		}
	}

	// Beside an address that fails, the non-public one is not in the retry hint.
	w := newIPWorld(t)
	w.local.Rcode(reverseName("10.0.0.1"), int(mdns.RcodeServerFailure))
	w.idb.setAll(ipStatus(500))
	w.sealProbes([]string{"10.0.0.1", "8.8.4.4"})
	f := ipoPartial(w, true, "10.0.0.1", "8.8.4.4", "--active", "--fields", "ptr,internetdb_ports")
	if inputs, _ := ipoRetry(t, f.hint); !slices.Equal(inputs, []string{"8.8.4.4"}) {
		t.Errorf("hint %q", f.hint)
	}
}

// Signals discard buffered lookup stdout and cancel outstanding requests, even after other
// addresses finished.
func TestIPOutcome_ASignalEndsTheCallWithNothingLeftRunning(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		addrs []string
	}{
		{"one address", []string{"8.8.4.4"}},
		{"after an address was answered", []string{"8.8.4.1", "8.8.4.2"}},
	} {
		for _, jsonMode := range modes {
			w := newIPWorld(t)
			w.h.signals = make(chan os.Signal, 2)
			w.h.eopts.HTTPTimeout = time.Minute
			for _, a := range c.addrs {
				w.seed(a)
			}
			var inFlight atomic.Int32
			arrived := make(chan struct{}, 8)
			w.idb.set(c.addrs[len(c.addrs)-1], func(_ http.ResponseWriter, r *http.Request) {
				inFlight.Add(1)
				defer inFlight.Add(-1)
				arrived <- struct{}{}
				<-r.Context().Done()
			})
			done := make(chan struct{})
			go func() {
				select {
				case <-arrived:
					w.h.signals <- os.Interrupt
				case <-done:
				}
			}()
			start := time.Now()
			f := w.h.failed(ipoRun(w, jsonMode, append(slices.Clone(c.addrs), "--timeout", "30s")...), 130, jsonMode)
			close(done)
			if f.code != "INTERRUPTED" {
				t.Errorf("%s (json=%v): %+v", c.name, jsonMode, f)
			}
			if el := time.Since(start); el > 5*time.Second {
				t.Errorf("%s (json=%v): the call took %v", c.name, jsonMode, el)
			}
			deadline := time.Now().Add(3 * time.Second)
			for inFlight.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if n := inFlight.Load(); n != 0 {
				t.Errorf("%s (json=%v): %d requests were still running after the call ended", c.name, jsonMode, n)
			}
		}
	}
}

// ---- render: the human layout ----

// goldenIP compares got with testdata/ip/<name>.txt, or rewrites it under -update-ip.
func goldenIP(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "ip", name+".txt")
	if *updateIP {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update-ip to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from the recorded output\n got: %q\nwant: %q", path, got, want)
	}
}

// Non-terminal output remains plain regardless of colour variables, with address headers and
// labelled sections.
func TestIPRender_PlainRecordIsPinned(t *testing.T) {
	t.Parallel()
	var first string
	for i, env := range []map[string]string{nil, {"COLORTERM": "truecolor", "TERM": "xterm-256color"}} {
		w := newIPWorld(t)
		for k, v := range env {
			w.h.setenv(k, v)
		}
		w.dns.A("web.example.com", "8.8.4.4")
		w.seed("8.8.4.4")
		if code := w.run("web.example.com"); code != 0 {
			t.Fatalf("exit %d\nstderr %s", code, w.h.stderr.String())
		}
		got := w.h.stdout.String()
		if w.h.stderr.Len() != 0 || strings.Contains(got, "\x1b") {
			t.Errorf("stdout %q\nstderr %q", got, w.h.stderr.String())
		}
		if i == 0 {
			first = got
		} else if got != first {
			t.Errorf("output with colour variables differs from the harness's\n got: %q\nwant: %q", got, first)
		}
	}
	goldenIP(t, "record-plain", first)
}

// Active sections appear after default data and before failure details.
func TestIPRender_ActiveRecordHasPortsTLSAndWeb(t *testing.T) {
	t.Parallel()
	const addr = "8.8.4.4"
	w := newIPWorld(t)
	w.dns.A("web.example.com", addr)
	w.seed(addr)
	ipoClosedExcept(w, addr, 22, 80, 443)
	w.listen(addr, 22, "SSH-2.0-nyx-test\r\n")
	w.serveHTTP(addr, 80, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Location", "https://web.example.com/")
		rw.WriteHeader(http.StatusMovedPermanently)
	}))
	w.serveTLS(addr, 443, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Server", "nyx-test-server")
		_, _ = fmt.Fprint(rw, `<html><head><title>Welcome</title></head><body>hi</body></html>`)
	}))
	if code := w.run("web.example.com", "--active"); code != 0 {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, w.h.stdout.String(), w.h.stderr.String())
	}
	out := w.h.stdout.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if lines[0] != "8.8.4.4 (web.example.com) [public]" {
		t.Errorf("header %q", lines[0])
	}
	var titles []string
	section := ""
	body := map[string][]string{}
	for _, l := range lines[1:] {
		switch {
		case l == "":
			section = ""
		case section == "":
			section = l
			titles = append(titles, l)
		default:
			body[section] = append(body[section], l)
		}
	}
	want := []string{"Owner", "Registration", "Names", "Provider", "Location", "Exposure", "Reverse IP", "Abusive networks", "Abusive ASN", "Spamhaus DROP networks", "Spamhaus ASN-DROP", "Not contacted", "Ports", "TLS", "Web", "Failures"}
	if !slices.Equal(titles, want) {
		t.Errorf("sections %v, want %v", titles, want)
	}
	if !slices.Equal(body["Not contacted"], []string{"none"}) {
		t.Errorf("Not contacted: %q", body["Not contacted"])
	}
	has := func(sec string, parts ...string) bool {
		return slices.ContainsFunc(body[sec], func(l string) bool {
			return strings.HasPrefix(l, "- ") && !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(l, p) })
		})
	}
	for _, c := range []struct {
		sec   string
		parts []string
	}{
		{"Ports", []string{"22", "open", "SSH-2.0-nyx-test"}},
		{"Ports", []string{"25", "closed"}},
		{"TLS", []string{"443", "web.example.com", "ok"}},
		{"Web", []string{"443", "https://web.example.com/", "ok", "200", "nyx-test-server", `"Welcome"`}},
		{"Web", []string{"80", "http://web.example.com/", "301", "https://web.example.com/"}},
	} {
		if !has(c.sec, c.parts...) {
			t.Errorf("%s has no item with %q:\n%s", c.sec, c.parts, strings.Join(body[c.sec], "\n"))
		}
	}
	if !slices.Equal(body["Failures"], []string{"none"}) {
		t.Errorf("Failures: %q", body["Failures"])
	}
}

// Terminal output aligns and wraps within width; removing colour does not change cell layout.
func TestIPRender_TerminalLayout(t *testing.T) {
	t.Parallel()
	const width = 70
	w := newIPWorld(t)
	w.dns.A("web.example.com", "8.8.4.4")
	w.seed("8.8.4.4")
	var lines []string
	for i := range 12 {
		lines = append(lines, fmt.Sprintf("virtual-host-number-%02d.customer-sites.example.org", i))
	}
	w.reverse("8.8.4.4", lines...)
	w.h.stdoutTTY = true
	w.h.setenv("COLUMNS", fmt.Sprint(width))
	w.h.setenv("NO_COLOR", "1")
	if code := w.run("web.example.com"); code != 0 {
		t.Fatalf("exit %d\nstderr %s", code, w.h.stderr.String())
	}
	out := unmargined(t, w.h.stdout.String())
	if strings.Contains(out, "\x1b") {
		t.Errorf("an escape byte under NO_COLOR:\n%q", out)
	}
	if got := maxCells(out); got > width {
		t.Errorf("a line is %d cells wide, want at most %d:\n%s", got, width, out)
	}
	ls := strings.Split(out, "\n")
	if ls[0] != "8.8.4.4 (web.example.com) [public]" {
		t.Errorf("header %q", ls[0])
	}
	// Each heading stands alone at the margin, with rows beneath it that are indented.
	for _, title := range []string{"Owner", "Registration", "Names", "Provider", "Location", "Exposure", "Reverse IP", "Failures"} {
		i := slices.Index(ls, title)
		if i < 1 || ls[i-1] != "" || i+1 >= len(ls) || !strings.HasPrefix(ls[i+1], "  ") {
			t.Errorf("the heading %q is not set apart above indented rows:\n%s", title, out)
		}
	}
	// The labels of a section share one column for their values.
	col := func(label, value string) int {
		re := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(label) + ` {2,}` + regexp.QuoteMeta(value) + `$`)
		loc := re.FindStringIndex(out)
		if loc == nil {
			t.Errorf("no row of %q and %q:\n%s", label, value, out)
			return -1
		}
		return strings.Index(out[loc[0]:loc[1]], value)
	}
	if a, b, c := col("ASN", "AS64500"), col("Name", "EXAMPLE-NET"), col("Prefix", "8.8.4.0/24"); a != b || b != c {
		t.Errorf("the values of Owner start at columns %d, %d and %d", a, b, c)
	}
	squeezed := strings.Join(strings.Fields(out), "")
	for _, l := range lines {
		if !strings.Contains(squeezed, l) {
			t.Errorf("%s is missing from the wrapped names:\n%s", l, out)
		}
	}

	// Coloured, the same cells with escape sequences added.
	w.h.setenv("NO_COLOR", "")
	w.h.setenv("COLORTERM", "truecolor")
	if code := w.run("web.example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	coloured := unmargined(t, w.h.stdout.String())
	if !strings.Contains(coloured, "\x1b[") || stripSGR(coloured) != out {
		t.Errorf("coloured output is not the plain layout with colour:\n%q", coloured)
	}
}

// ipoHostile wraps text in a colour sequence and a command that sets the terminal's title, which
// a terminal would act on.
func ipoHostile(text string) string {
	return "\x1b[31m" + text + "\x1b]0;pwned-title\x07\x1b[0m"
}

// ipoHostileCase describes hostile source/target text and the cleaned payload expected to
// survive display.
type ipoHostileCase struct {
	name     string
	fragment string
	facts    func(f *ipFacts)
	banner   string
	title    string
}

// run looks the address up under --active with the case's text, on a terminal or not, and checks
// the output.
func (c ipoHostileCase) run(t *testing.T, addr string, terminal bool) {
	t.Helper()
	w := newIPWorld(t)
	w.seed(addr, c.facts)
	ipoClosedExcept(w, addr, 22, 80)
	w.listen(addr, 22, c.banner)
	w.serveHTTP(addr, 80, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(rw, "<html><head><title>"+c.title+"</title></head></html>")
	}))
	w.h.stdoutTTY = terminal
	if terminal {
		w.h.setenv("COLORTERM", "truecolor")
	}
	if code := w.run(addr, "--active"); code != 0 && code != 7 {
		t.Fatalf("terminal=%v: exit %d\nstderr %s", terminal, code, w.h.stderr.String())
	}
	out := stripSGR(w.h.stdout.String())
	for i, r := range out {
		if r != '\n' && (r < 0x20 || (r >= 0x7f && r <= 0x9f)) {
			t.Errorf("terminal=%v: control character %U at %d in the output:\n%q", terminal, r, i, out)
			break
		}
	}
	for _, bad := range []string{"[31m", "[0m", "pwned-title"} {
		if strings.Contains(out, bad) {
			t.Errorf("terminal=%v: %q reached the output:\n%q", terminal, bad, out)
		}
	}
	if c.fragment != "" && !strings.Contains(out, c.fragment) {
		t.Errorf("terminal=%v: the text %q is not shown:\n%q", terminal, c.fragment, out)
	}
}

// Source text cannot execute terminal controls in plain or coloured output.
func TestIPRender_HostileTextIsSanitised(t *testing.T) {
	t.Parallel()
	none := func(*ipFacts) {}
	for _, c := range []ipoHostileCase{
		{name: "banner", fragment: "bannertext", facts: none, banner: "SSH-2.0-" + ipoHostile("bannertext") + "\r\n", title: "ok"},
		{name: "page title", fragment: "titletext", facts: none, title: ipoHostile("titletext")},
		{name: "RDAP organisation", fragment: "orgtext", facts: func(f *ipFacts) { f.Org = ipoHostile("orgtext") }, title: "ok"},
		{name: "PTR name", facts: func(f *ipFacts) { f.PTR = []string{"ptr" + ipoHostile("ptrtext") + ".example.net"} }, title: "ok"},
		{name: "InternetDB hostname", facts: func(f *ipFacts) { f.Hostnames = []string{"idb" + ipoHostile("idbtext") + ".example.net"} }, title: "ok"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			for _, terminal := range []bool{false, true} {
				c.run(t, "8.8.4.4", terminal)
			}
		})
	}
}

// writes are the bytes written to both streams of a call, in order, so a test can see which came
// first.
type ipoOrdered struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *ipoOrdered) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

// WARN lines go to stderr and not stdout, and the error: lines of a partial result come after the
// records.
func TestIPRender_ErrorLinesFollowTheRecordsAndWarningsGoToStderr(t *testing.T) {
	t.Parallel()
	setup := func() *ipWorld {
		w := newIPWorld(t)
		w.seed("8.8.4.1")
		w.seed("8.8.4.2")
		w.idb.set("8.8.4.2", ipStatus(500))
		w.ht.setAll(ipReply(200, ipoExceeded))
		return w
	}

	w := setup()
	f := ipoPartial(w, false, "8.8.4.1", "8.8.4.2")
	out := w.h.stdout.String()
	if !strings.Contains(out, "8.8.4.1 [public]") || !strings.Contains(out, "8.8.4.2 [public]") {
		t.Errorf("stdout lacks the records:\n%s", out)
	}
	for _, bad := range []string{"error:", "WARN", "hint:", "resets daily"} {
		if strings.Contains(out, bad) {
			t.Errorf("stdout holds %q:\n%s", bad, out)
		}
	}
	if warns := w.h.logMsgs("WARN"); len(warns) != 1 || !strings.Contains(warns[0], "resets daily") {
		t.Errorf("WARN lines %q", warns)
	}
	if inputs, _ := ipoRetry(t, f.hint); !slices.Equal(inputs, []string{"8.8.4.2"}) || !f.transient {
		t.Errorf("error %+v", f)
	}

	// Both streams in one, the error: lines are after the last record.
	w = setup()
	var both ipoOrdered
	d := w.h.deps()
	d.Stdout, d.Stderr = &both, &both
	if code := cli.Execute(context.Background(), []string{"ip", "8.8.4.1", "8.8.4.2"}, d); code != 7 {
		t.Fatalf("exit %d\n%s", code, both.buf.String())
	}
	all := both.buf.String()
	lastRecord, firstError := strings.LastIndex(all, "8.8.4.2 [public]"), strings.Index(all, "error:")
	if lastRecord < 0 || firstError < 0 || firstError < lastRecord {
		t.Errorf("the error: lines are not after the records:\n%s", all)
	}
}

// ---- help ----

// ipoFieldsLine is the line of the help that lists the names --fields accepts.
func ipoFieldsLine(t *testing.T, help string) string {
	t.Helper()
	for l := range strings.SplitSeq(help, "\n") {
		if strings.HasPrefix(l, "Fields accepted by --fields: ") && strings.Contains(l, "asn") {
			return l
		}
	}
	t.Fatalf("no line of the field names:\n%s", help)
	return ""
}

// ipoFieldNames are every name --fields accepts under --active, and all.
func ipoFieldNames() []string {
	all := ipAllKeys(true)
	return append(slices.Clone(all[3:len(all)-1]), "all")
}

// Root help exposes IP examples, flags and fields without recon-only settings.
func TestIPHelp_RootListsIP(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if code := h.execRoot("--help"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	root := h.stdout.String()
	if got := strings.Count(root, "\nnyx ip "); got != 1 {
		t.Fatalf("the root help has %d entries for ip:\n%s", got, root)
	}
	_, entry, _ := strings.Cut(root, "\nnyx ip ")
	entry, _, _ = strings.Cut(entry, "\n\n")
	for _, want := range []string{"Example: nyx ip ", "ip flags:", "--active", "--fields", "--timeout duration"} {
		if !strings.Contains(entry, want) {
			t.Errorf("ip's entry lacks %q:\n%s", want, entry)
		}
	}
	for _, not := range []string{"--config", "--output-dir", "--rate-per-host", "--engagement", "--limit", "--match"} {
		if strings.Contains(entry, not) {
			t.Errorf("ip's entry lists %s", not)
		}
	}
	fields := ipoFieldsLine(t, entry)
	for _, name := range ipoFieldNames() {
		if !slices.Contains(strings.FieldsFunc(fields, func(r rune) bool { return r == ',' || r == ' ' || r == ':' || r == '(' || r == ')' }), name) {
			t.Errorf("the fields line lacks %q: %s", name, fields)
		}
	}
	exampleLine := ""
	for l := range strings.SplitSeq(root, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "nyx ip ") && strings.Contains(l, "--json") {
			exampleLine = l
		}
	}
	if exampleLine == "" {
		t.Errorf("the root help's examples have no call of nyx ip that passes --json:\n%s", root)
	}
}

// IP help aliases agree on examples, active-only fields, shared flags and exit codes without
// --config.
func TestIPHelp_IPHelpIsTheFullHelp(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if code := h.execRoot("ip", "--help"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	own := h.stdout.String()
	if code := h.execRoot("help", "ip"); code != 0 || h.stdout.String() != own {
		t.Errorf("nyx help ip differs from nyx ip --help")
	}
	for _, l := range exampleLines(t, own) {
		if !strings.HasPrefix(strings.TrimSpace(l), "nyx ip ") {
			t.Errorf("example %q is not a call of nyx ip", l)
		}
	}
	if !strings.Contains(own, "--active") || !strings.Contains(own, "--fields string") || !strings.Contains(own, "--timeout duration") ||
		!strings.Contains(own, "--json") || !strings.Contains(own, "nyx ip <input>") || lastLine(own) != exitCodesLine {
		t.Errorf("nyx ip --help:\n%s", own)
	}
	for _, not := range []string{"--config", "--output-dir", "--rate-per-host", "--limit", "--match"} {
		if strings.Contains(own, not) {
			t.Errorf("nyx ip --help lists %s:\n%s", not, own)
		}
	}
	fields := ipoFieldsLine(t, own)
	tokens := strings.FieldsFunc(fields, func(r rune) bool { return r == ',' || r == ' ' || r == ':' || r == '(' || r == ')' })
	for _, name := range ipoFieldNames() {
		if !slices.Contains(tokens, name) {
			t.Errorf("the fields line lacks %q: %s", name, fields)
		}
	}
	// The names only --active gives are marked: --active is named on the fields line or the line after.
	lines := strings.Split(own, "\n")
	at := slices.Index(lines, fields)
	if !strings.Contains(fields, "--active") && (at+1 >= len(lines) || !strings.Contains(lines[at+1], "--active")) {
		t.Errorf("the help does not say that some of the names need --active:\n%s", own)
	}
	if code := h.execRoot("ip", "--config", "x.yaml", "8.8.4.4"); code != 2 {
		t.Errorf("--config: exit %d, want 2", code)
	}
}
