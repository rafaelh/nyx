package cli_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Parent names: every name between a found
// in-scope hostname and its input root is resolved by resolve.

// parentWorld is a world whose crt.sh returns found under example.com, with owners for the
// addresses the tests give their names.
func parentWorld(t *testing.T, found ...string) *world {
	t.Helper()
	w := newWorld(t)
	w.crtsh(map[string][]string{"example.com": found}, nil)
	w.owner("203.0.113.10", 64500, "ACME-NET")
	w.owner("203.0.113.11", 64500, "ACME-NET")
	return w
}

// parentListedIn returns the engagement's output files (not the state under .nyx/) that name
// host as a whole name, not as the suffix of a longer one.
func parentListedIn(w *world, host string) []string {
	w.t.Helper()
	re := regexp.MustCompile(`(?:^|[^a-z0-9.-])` + regexp.QuoteMeta(host) + `(?:$|[^a-z0-9.-]|\.(?:$|[^a-z0-9-]))`)
	root := w.h.eng(eng)
	var hits []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".nyx" {
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if re.Match(b) {
			rel, _ := filepath.Rel(root, p)
			hits = append(hits, rel)
		}
		return nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return hits
}

// parentCheckResolve checks that resolve ran a parent job for each name and that its reported
// job count covers every resolve job, the parent jobs included.
func parentCheckResolve(t *testing.T, w *world, names ...string) {
	t.Helper()
	done := w.h.completed(eng, "resolve")
	for _, n := range names {
		if !slices.Contains(done, "parent|"+n) {
			t.Errorf("resolve has no completed parent job for %s: %v", n, done)
		}
	}
	st := lastState(w.h.events(), "resolve")
	if st == nil || st.str("state") != "done" || st.num("jobs") != len(done) {
		t.Errorf("resolve state = %v, want done with %d jobs (its parent jobs included)", st, len(done))
	}
}

func TestParentNames_ResolvingParentIsListedAndAskedOnce(t *testing.T) {
	t.Parallel()
	w := parentWorld(t, "a.b.example.com")
	w.dns.A("a.b.example.com", "203.0.113.10")
	w.dns.A("b.example.com", "203.0.113.11")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, "b.example.com") || !slices.Contains(got, "a.b.example.com") {
		t.Errorf("subdomains.txt = %v, want the resolving parent b.example.com listed", got)
	}
	if find(w.table(eng, "resolutions.csv"), "value", "203.0.113.11") == nil {
		t.Errorf("resolutions.csv has no address of the parent: %s", w.file(eng, "resolutions.csv"))
	}
	// The parent is asked once over all of the run's passes, by resolve and by nothing else.
	if a, aaaa := w.dns.Count("b.example.com", "A"), w.dns.Count("b.example.com", "AAAA"); a != 1 || aaaa != 1 {
		t.Errorf("b.example.com asked A %d and AAAA %d times, want once each", a, aaaa)
	}
	parentCheckResolve(t, w, "b.example.com")
}

func TestParentNames_ParentWithNoRecordsIsInNoFileUntilASourceFindsIt(t *testing.T) {
	t.Parallel()
	// q.example.com is unknown to the fake (NXDOMAIN); p.q.example.com sits under a zone that
	// answers NOERROR with no records.
	w := parentWorld(t, "a.p.q.example.com")
	w.dns.A("a.p.q.example.com", "203.0.113.10")
	w.dns.NoDataSuffix("q.example.com")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "a.p.q.example.com") {
		t.Fatalf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
	}
	for _, p := range []string{"p.q.example.com", "q.example.com"} {
		if w.dns.Count(p, "A") == 0 {
			t.Errorf("parent %s was never resolved", p)
		}
		if hits := parentListedIn(w, p); len(hits) != 0 {
			t.Errorf("parent %s with no records is listed in %v, want no file", p, hits)
		}
	}
	if got := w.lines(eng, "unresolved.txt"); slices.Contains(got, "p.q.example.com") || slices.Contains(got, "q.example.com") {
		t.Errorf("unresolved.txt = %v, want no parent with no records", got)
	}

	// A real source now finds both: they are hostnames like any other, and do not resolve.
	w.crtsh(map[string][]string{"example.com": {"a.p.q.example.com", "p.q.example.com", "q.example.com"}}, nil)
	if code := w.run("--passive", "--redo", "crtsh", "example.com"); code != 0 {
		t.Fatalf("second run exit %d\n%s", code, w.h.stderr.String())
	}
	got := w.lines(eng, "unresolved.txt")
	for _, p := range []string{"p.q.example.com", "q.example.com"} {
		if !slices.Contains(got, p) {
			t.Errorf("unresolved.txt = %v, want %s once crt.sh returns it", got, p)
		}
		if hits := parentListedIn(w, p); !slices.Contains(hits, "unresolved.txt") {
			t.Errorf("%s is listed in %v, want unresolved.txt among them", p, hits)
		}
	}
}

func TestParentNames_ResolvedWhenLearningIsOff(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"skip learned-names", []string{"--skip", "learned-names"}},
		{"no permutations", []string{"--no-permutations"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := parentWorld(t, "a.b.example.com")
			w.dns.A("a.b.example.com", "203.0.113.10")
			w.dns.A("b.example.com", "203.0.113.11")
			args := append(append([]string{"--passive"}, tc.args...), "example.com")
			if code := w.run(args...); code != 0 {
				t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
			}
			if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, "b.example.com") {
				t.Errorf("subdomains.txt = %v, want the parent b.example.com", got)
			}
			if a := w.dns.Count("b.example.com", "A"); a != 1 {
				t.Errorf("b.example.com asked A %d times, want once", a)
			}
			parentCheckResolve(t, w, "b.example.com")
		})
	}
}

func TestParentNames_ExcludedParentThatResolvesIsExcluded(t *testing.T) {
	t.Parallel()
	// b.example.com is excluded by name; d.example.com by the address it resolves to.
	w := parentWorld(t, "a.b.example.com", "c.d.example.com")
	w.dns.A("a.b.example.com", "203.0.113.10")
	w.dns.A("b.example.com", "203.0.113.11")
	w.dns.A("c.d.example.com", "203.0.113.10")
	w.dns.A("d.example.com", "192.0.2.7")
	w.owner("192.0.2.7", 64500, "ACME-NET")
	if code := w.run("--passive", "-x", "b.example.com", "-x", "192.0.2.0/24", "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	ex := w.table(eng, "excluded.csv")
	for _, p := range []string{"b.example.com", "d.example.com"} {
		if find(ex, "value", p) == nil {
			t.Errorf("excluded.csv has no %s: %s", p, w.file(eng, "excluded.csv"))
		}
		if slices.Contains(w.lines(eng, "subdomains.txt"), p) {
			t.Errorf("excluded parent %s is in subdomains.txt", p)
		}
	}
}

func TestParentNames_NoParentOfACandidateIsQueried(t *testing.T) {
	t.Parallel()
	w := parentWorld(t, "www.example.com")
	// A CNAME target under another registrable domain, and a PTR name from an in-scope netblock
	// under another one: neither is under an input root.
	w.dns.CNAME("www.example.com", "edge.cdn.example.net")
	w.dns.A("edge.cdn.example.net", "203.0.113.10")
	w.dns.PTR("198.51.100.2", "host.deep.other.org")
	w.dns.A("host.deep.other.org", "198.51.100.2")
	if code := w.run("--passive", "--cidr", "198.51.100.0/30", "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	// The PTR name resolves into the netblock, so it is in scope by its address; it is still under
	// no input root, so its parents are not names to resolve.
	if find(w.table(eng, "scope.csv"), "value", "host.deep.other.org") == nil {
		t.Fatalf("the PTR name is not in scope by address: %s", w.file(eng, "scope.csv"))
	}
	for _, typ := range []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA", "SRV"} {
		for _, n := range w.dns.Queried(typ) {
			switch n {
			case "cdn.example.net", "example.net", "deep.other.org", "other.org", "net", "org":
				t.Errorf("%s of a candidate's parent %s was queried", typ, n)
			}
		}
	}
	for _, k := range w.h.completed(eng, "resolve") {
		if strings.HasPrefix(k, "parent|") && !strings.HasSuffix(k, ".example.com") {
			t.Errorf("resolve has a parent job %s outside the input root", k)
		}
	}
}

func TestParentNames_ParentWithNoRecordsIsAskedOnceWithLearningOn(t *testing.T) {
	t.Parallel()
	w := parentWorld(t, "a.p.q.example.com")
	w.dns.A("a.p.q.example.com", "203.0.113.10")
	w.dns.NoDataSuffix("q.example.com")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	// Learning ran: the label p was tried under the root.
	if n := w.dns.Count("p.example.com", "A"); n != 1 {
		t.Errorf("p.example.com asked A %d times, want once (learning must be on in this test)", n)
	}
	// Both parents are populated zones whose labels learning knows, but only their parent jobs
	// ask them.
	for _, p := range []string{"p.q.example.com", "q.example.com"} {
		if n := w.dns.Count(p, "A"); n != 1 {
			t.Errorf("parent %s with no records asked A %d times in the run, want once", p, n)
		}
	}
}

func TestParentNames_EveryLevelUpToButNotIncludingTheRoot(t *testing.T) {
	t.Parallel()
	w := parentWorld(t, "x.a.b.example.com")
	w.dns.A("x.a.b.example.com", "203.0.113.10")
	w.dns.A("a.b.example.com", "203.0.113.11")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	got := w.lines(eng, "subdomains.txt")
	if !slices.Contains(got, "a.b.example.com") {
		t.Errorf("subdomains.txt = %v, want the resolving parent a.b.example.com", got)
	}
	if slices.Contains(got, "b.example.com") {
		t.Errorf("subdomains.txt = %v, want no b.example.com (it has no records)", got)
	}
	for _, p := range []string{"a.b.example.com", "b.example.com"} {
		if n := w.dns.Count(p, "A"); n != 1 {
			t.Errorf("parent %s asked A %d times, want once", p, n)
		}
	}
	parentCheckResolve(t, w, "a.b.example.com", "b.example.com")
	for _, k := range w.h.completed(eng, "resolve") {
		if k == "parent|example.com" || k == "parent|com" {
			t.Errorf("resolve ran %s: the input root and names above it are not parents", k)
		}
	}
	if !slices.Contains(w.h.completed(eng, "resolve"), "example.com") {
		t.Error("the input root must still be resolved by its normal job")
	}
	for _, typ := range []string{"A", "AAAA"} {
		if n := w.dns.Count("com", typ); n != 0 {
			t.Errorf("com asked %s %d times: nothing above the input root is resolved", typ, n)
		}
	}
}
