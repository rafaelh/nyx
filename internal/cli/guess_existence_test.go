package cli_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

// The existence rule for guessed names: a name that learning or permutations tries
// exists only when its A lookup returns a CNAME or an A address. Each test runs one world in
// which learning, a permutations root job and a permutations seed job each try a name the test
// scripts, so a change to the rule in either procedure fails it.
//
// The world (guessWorld) has two input roots, example.com and corp.net, and crt.sh gives
// staging.example.com and api.corp.net, both with addresses. So:
//   - learning learns staging and api, and tries staging.corp.net and api.example.com;
//   - the permutations root job tries the wordlist (dev, test) under each root;
//   - the permutations seed jobs try variants of staging.example.com and api.corp.net, among
//     them staging-dev.example.com and api-dev.corp.net.
//
// Neither procedure tries the others' names: staging and api are not wordlist words, and dev is
// one, so learning leaves dev.corp.net to the root job.

const (
	guessWords   = "dev\ntest\n"
	guessLearned = "staging.corp.net" // tried only by learning
	guessRoot    = "dev.corp.net"     // tried only by the permutations root job
	guessSeed    = "api-dev.corp.net" // tried only by the permutations seed job of api.corp.net
)

// guessTried are the three scripted guessed names and who tries each.
var guessTried = []struct{ name, by string }{
	{guessLearned, "learned-names"},
	{guessRoot, "the permutations root job"},
	{guessSeed, "the permutations seed job"},
}

// guessWorld is the world described above, with a wordlist of guessWords.
func guessWorld(t *testing.T) (*world, string) {
	t.Helper()
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", guessWords)
	w.crtsh(map[string][]string{"example.com": {"staging.example.com"}, "corp.net": {"api.corp.net"}}, nil)
	w.dns.A("staging.example.com", "203.0.113.5")
	w.dns.A("api.corp.net", "203.0.113.6")
	return w, wl
}

// guessPositives gives each procedure one tried name under example.com that has an A address, so
// a rule that records nothing fails: api.example.com (learning), test.example.com (the root job)
// and staging-dev.example.com (the seed job of staging.example.com).
func guessPositives(w *world) []string {
	names := []string{"api.example.com", "test.example.com", "staging-dev.example.com"}
	for i, n := range names {
		w.dns.A(n, "203.0.113."+[]string{"20", "21", "22"}[i])
	}
	return names
}

// guessRun runs a passive engagement of both roots with one worker, so names are asked in the
// order the procedures yield them.
func guessRun(w *world, wl string, args ...string) int {
	full := append([]string{"--passive", "--concurrency", "1", "--wordlist", wl}, args...)
	return w.run(append(full, "example.com", "corp.net")...)
}

// guessHostnames are the keys of every hostname record the engagement holds, shown or not.
func guessHostnames(w *world) []string {
	var out []string
	for k := range w.obsAttrs(eng, "hostname") {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// guessProbe matches the wildcard check's random probe names (16 hex characters).
var guessProbe = regexp.MustCompile(`^[0-9a-f]{16}\.`)

// guessAAAAOfNonHostnames are the names asked for AAAA that are not hostname records, input
// roots or wildcard probes: resolve asks AAAA only of hostnames and of parent names, and
// every hostname in guessWorld sits directly under its root, so there is no parent name and any
// such name was asked AAAA by guessing.
func guessAAAAOfNonHostnames(w *world) []string {
	hosts := guessHostnames(w)
	var out []string
	for _, n := range w.dns.Queried("AAAA") {
		if slices.Contains(hosts, n) || n == "example.com" || n == "corp.net" || guessProbe.MatchString(n) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// guessCheckAsked fails unless each scripted name was asked for A, so the test is not passing
// because nothing tried it.
func guessCheckAsked(t *testing.T, w *world) {
	t.Helper()
	for _, g := range guessTried {
		if n := w.dns.Count(g.name, "A"); n == 0 {
			t.Errorf("%s was never asked for A; %s should try it", g.name, g.by)
		}
	}
}

// guessCheckPositives fails unless each name that has an A address became a hostname.
func guessCheckPositives(t *testing.T, w *world, names []string) {
	t.Helper()
	hosts := w.lines(eng, "subdomains.txt")
	for _, n := range names {
		if !slices.Contains(hosts, n) {
			t.Errorf("%s has an A address yet is not in subdomains.txt: %v", n, hosts)
		}
	}
}

// A zone that answers NOERROR with no records for every name (as a Cloudflare-hosted zone does)
// gives no hostname, whichever procedure guessed the name.
func TestGuessExistence_NoRecordsZoneRecordsNoHostname(t *testing.T) {
	t.Parallel()
	w, wl := guessWorld(t)
	w.dns.NoDataSuffix("corp.net")
	pos := guessPositives(w)
	if code := guessRun(w, wl); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	guessCheckAsked(t, w)
	if variants := derivedUnder(w, "api", "corp.net"); len(variants) == 0 {
		t.Error("no variant of api.corp.net was asked; the seed job should try them")
	}
	hosts := guessHostnames(w)
	for _, g := range guessTried {
		if slices.Contains(hosts, g.name) {
			t.Errorf("%s answered NOERROR with no records, yet %s recorded it", g.name, g.by)
		}
	}
	for _, h := range hosts {
		if strings.HasSuffix(h, ".corp.net") && h != "api.corp.net" {
			t.Errorf("%s is a hostname, but every guessed name under corp.net answers NOERROR with no records", h)
		}
	}
	guessCheckPositives(t, w, pos)
}

// A tried name with only an AAAA record is not a name, and guessing never asks AAAA.
func TestGuessExistence_AAAAOnlyIsNotANameAndAAAAIsNotAsked(t *testing.T) {
	t.Parallel()
	w, wl := guessWorld(t)
	for _, g := range guessTried {
		w.dns.A(g.name, "2001:db8::5") // an IPv6 address only
	}
	pos := guessPositives(w)
	if code := guessRun(w, wl); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	guessCheckAsked(t, w)
	hosts := guessHostnames(w)
	for _, g := range guessTried {
		if slices.Contains(hosts, g.name) {
			t.Errorf("%s has only an AAAA record, yet %s recorded it", g.name, g.by)
		}
		if n := w.dns.Count(g.name, "AAAA"); n != 0 {
			t.Errorf("%s was asked for AAAA %d times; guessing asks only A (%s tried it)", g.name, n, g.by)
		}
	}
	if extra := guessAAAAOfNonHostnames(w); len(extra) != 0 {
		t.Errorf("names that never became hostnames were asked for AAAA: %v", extra)
	}
	guessCheckPositives(t, w, pos)
}

// A tried name whose CNAME points at a name that does not exist (NXDOMAIN) exists: the dangling
// alias is what a takeover check needs.
func TestGuessExistence_CNAMEToNXDOMAINExists(t *testing.T) {
	t.Parallel()
	w, wl := guessWorld(t)
	for i, g := range guessTried {
		w.dns.CNAME(g.name, []string{"gone1", "gone2", "gone3"}[i]+".example.net") // the targets answer NXDOMAIN
	}
	if code := guessRun(w, wl); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	hosts := w.lines(eng, "subdomains.txt")
	for _, g := range guessTried {
		if !slices.Contains(hosts, g.name) {
			t.Errorf("%s has a CNAME to a name that does not exist, yet %s did not record it: %v", g.name, g.by, hosts)
		}
	}
}

// SERVFAIL on a tried name records nothing, fails no job and ends the run with exit 0, and the
// name is not asked again on the next run.
func TestGuessExistence_SERVFAILRecordsNothingAndCompletes(t *testing.T) {
	t.Parallel()
	w, wl := guessWorld(t)
	for _, g := range guessTried {
		w.dns.Rcode(g.name, mdns.RcodeServerFailure)
	}
	pos := guessPositives(w)
	if code := guessRun(w, wl); code != 0 {
		t.Fatalf("exit %d, want 0: SERVFAIL on a tried name is not a failure\n%s", code, w.h.stderr.String())
	}
	guessCheckAsked(t, w)
	hosts := guessHostnames(w)
	for _, g := range guessTried {
		if slices.Contains(hosts, g.name) {
			t.Errorf("%s answered SERVFAIL, yet %s recorded it", g.name, g.by)
		}
	}
	for _, p := range []string{"learned-names", "permutations"} {
		if f := w.h.failedJobs(p); len(f) != 0 {
			t.Errorf("%s failed jobs on SERVFAIL: %v", p, f)
		}
		if st, _ := stateOf(w, p); st != "done" {
			t.Errorf("%s = %q, want done", p, st)
		}
	}
	guessCheckPositives(t, w, pos)

	before := map[string]int{}
	for _, g := range guessTried {
		before[g.name] = w.dns.Count(g.name, "A")
	}
	if code := guessRun(w, wl); code != 0 {
		t.Fatalf("second run: exit %d\n%s", code, w.h.stderr.String())
	}
	for _, g := range guessTried {
		if n := w.dns.Count(g.name, "A"); n != before[g.name] {
			t.Errorf("%s was asked again on the next run (%d queries, was %d); %s completed its job", g.name, n, before[g.name], g.by)
		}
	}
}

// --- The learned-names cap ---

// A cap below 1 is invalid input: exit 2 naming the setting, before any DNS query.
func TestGuessCap_ZeroExits2(t *testing.T) {
	t.Parallel()
	w, wl := guessWorld(t)
	code := guessRun(w, wl, "--learned-names-max-names", "0")
	f := w.h.failed(code, 2, true)
	if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "learned_names.max_names") ||
		!slices.Equal(f.inputOf("learned_names.max_names"), []string{"0"}) {
		t.Errorf("error = %s %q (input %v), want INVALID_INPUT naming learned_names.max_names and its value 0", f.code, f.msg, f.input)
	}
	if n := w.dns.Total(); n != 0 {
		t.Errorf("%d DNS queries were sent after a validation error, want none", n)
	}
}
