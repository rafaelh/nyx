package cli_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/spamhaus"
)

// The stale hint: a source whose oldest list in use, and whose last successful check, are both more
// than 30 days old is named in one line on stderr after a recon run or a nyx ip call, or in
// meta.warnings under --json. The tests' built-in copies are fixed and old (see staleDrop); the
// harness's clock is 2026-11-01.

// The dates of the old built-in copies: ipapi.is's lists, and Spamhaus's (staleDrop). The oldest of
// each source is what its hint gives.
const (
	staleIpapiNets = "2026-09-14"
	staleIpapiASNs = "2026-09-10"
)

// staleDrop is Spamhaus's three lists dated 2026-09-20, 2026-09-12 (23:30 UTC) and 2026-09-25.
func staleDrop(tb testing.TB, nets []spamhaus.NetworkEntry, asns []spamhaus.ASNEntry) *spamhaus.Lists {
	tb.Helper()
	return dropListsOn(tb, time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC), time.Date(2026, 9, 12, 23, 30, 0, 0, time.UTC),
		time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC), nets, asns)
}

// The hints the old built-in copies give, and the warnings they are under --json.
const (
	staleSpamhausHint = "hint: Spamhaus DROP data is from 2026-09-12; run nyx setup --update-threat-data"
	staleIpapiHint    = "hint: ipapi.is abuse data is from 2026-09-10; run nyx setup --update-threat-data"
)

var (
	staleSpamhausWarning = strings.TrimPrefix(staleSpamhausHint, "hint: ")
	staleIpapiWarning    = strings.TrimPrefix(staleIpapiHint, "hint: ")
)

// withStaleData gives the harness the old built-in copies.
func withStaleData(h *harness) {
	h.abusive = abSnapshotOn(staleIpapiNets, staleIpapiASNs, nil, nil)
	h.drop = staleDrop(h.t, nil, nil)
}

// sameSet reports whether got holds exactly the lines of want, in any order.
func sameSet(got, want []string) bool {
	got, want = slices.Clone(got), slices.Clone(want)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

// warningsLike are the entries of a list of warnings that speak of updating the threat data.
func warningsLike(ws []string) []string {
	var out []string
	for _, w := range ws {
		if strings.Contains(w, "--update-threat-data") {
			out = append(out, w)
		}
	}
	return out
}

// A recon run with old data prints one hint line for each stale source, with the source's oldest
// date, and the call is otherwise as it would be.
func TestStaleHint_Recon(t *testing.T) {
	t.Parallel()
	fresh := newHarness(t, noop())
	if code := fresh.exec("example.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, fresh.stderr.String())
	}
	if l := staleHintLines(fresh); len(l) != 0 {
		t.Errorf("fresh data: hint lines %q", l)
	}
	h := newHarness(t, noop())
	withStaleData(h)
	if code := h.exec("example.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := staleHintLines(h); !sameSet(got, []string{staleSpamhausHint, staleIpapiHint}) {
		t.Errorf("hint lines %q, want exactly %q and %q\nstderr:\n%s", got, staleSpamhausHint, staleIpapiHint, h.stderr.String())
	}
	for _, m := range h.messages("warning", "") {
		if strings.Contains(m, "--update-threat-data") {
			t.Errorf("the hint is a warning event in the human layout: %q", m)
		}
	}
	if h.stdout.String() != fresh.stdout.String() {
		t.Errorf("stdout differs with old data:\n%q\n%q", h.stdout.String(), fresh.stdout.String())
	}
}

// nyx ip names a stale source only when a selected key reads it: abusive_* read ipapi.is, drop_*
// read Spamhaus, and the other keys neither.
func TestStaleHint_IPOnlyForTheSourcesItsKeysRead(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fields string // "" for the default selection
		want   []string
	}{
		{"", []string{staleSpamhausHint, staleIpapiHint}},
		{"asn,as_name,ptr", nil},
		{"abusive_networks", []string{staleIpapiHint}},
		{"abusive_asn", []string{staleIpapiHint}},
		{"drop_networks", []string{staleSpamhausHint}},
		{"drop_asn", []string{staleSpamhausHint}},
		{"drop_networks,abusive_asn", []string{staleSpamhausHint, staleIpapiHint}},
	} {
		t.Run("fields="+c.fields, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			withStaleData(w.h)
			w.seed("8.8.4.4")
			args := []string{"8.8.4.4"}
			if c.fields != "" {
				args = append(args, "--fields", c.fields)
			}
			if code := w.run(args...); code != 0 {
				t.Fatalf("exit %d: %s", code, w.h.stderr.String())
			}
			if got := staleHintLines(w.h); !sameSet(got, c.want) {
				t.Errorf("hint lines %q, want %q\nstderr:\n%s", got, c.want, w.h.stderr.String())
			}
		})
	}
}

// Under --json the notice is an entry of meta.warnings, for recon and for nyx ip, with --quiet too,
// and nothing is printed on stderr.
func TestStaleHint_UnderJSONIsAWarning(t *testing.T) {
	t.Parallel()
	want := []string{staleSpamhausWarning, staleIpapiWarning}
	for _, quiet := range []bool{false, true} {
		extra := []string{"--json"}
		if quiet {
			extra = append(extra, "--quiet")
		}
		t.Run(strings.Join(extra, " "), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, noop())
			withStaleData(h)
			if code := h.exec(append([]string{"example.com"}, extra...)...); code != 0 {
				t.Fatalf("recon: exit %d: %s", code, h.stderr.String())
			}
			if got := warningsLike(h.envelope().Meta.Warnings); !sameSet(got, want) {
				t.Errorf("recon meta.warnings %q, want %q", got, want)
			}
			if l := staleHintLines(h); len(l) != 0 {
				t.Errorf("recon printed %q under --json", l)
			}
			w := newIPWorld(t)
			withStaleData(w.h)
			w.seed("8.8.4.4")
			args := []string{"8.8.4.4"}
			if quiet {
				args = append(args, "--quiet")
			}
			if code := w.runJSON(args...); code != 0 {
				t.Fatalf("nyx ip: exit %d: %s", code, w.h.stderr.String())
			}
			if got := warningsLike(w.h.ipEnvelope().Meta.Warnings); !sameSet(got, want) {
				t.Errorf("nyx ip meta.warnings %q, want %q", got, want)
			}
			if l := staleHintLines(w.h); len(l) != 0 {
				t.Errorf("nyx ip printed %q under --json", l)
			}
		})
	}
}

// --quiet alone prints no hint, and neither does a usage error.
func TestStaleHint_NotPrinted(t *testing.T) {
	t.Parallel()
	recon := []struct {
		name string
		args []string
	}{
		{"recon --quiet", []string{"example.com", "--quiet"}},
		{"recon bad value", []string{"example.com", "--concurrency", "abc"}},
		{"recon bad flag", []string{"example.com", "--no-such-flag"}},
		{"recon no inputs", nil},
	}
	for _, c := range recon {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, noop())
			withStaleData(h)
			h.exec(c.args...)
			if l := staleHintLines(h); len(l) != 0 {
				t.Errorf("hint lines %q\nstderr:\n%s", l, h.stderr.String())
			}
		})
	}
	ip := []struct {
		name string
		args []string
		code int
	}{
		{"ip --quiet", []string{"8.8.4.4", "--quiet"}, 0},
		{"ip unknown field", []string{"8.8.4.4", "--fields", "drop_networks,bogus"}, 2},
		{"ip bad input", []string{"https://example.com/x"}, 2},
	}
	for _, c := range ip {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			withStaleData(w.h)
			w.seed("8.8.4.4")
			if code := w.run(c.args...); code != c.code {
				t.Fatalf("exit %d, want %d: %s", code, c.code, w.h.stderr.String())
			}
			if l := staleHintLines(w.h); len(l) != 0 {
				t.Errorf("hint lines %q\nstderr:\n%s", l, w.h.stderr.String())
			}
		})
	}
}

// In recon, the stale hints come after the no-config hint and before the error.
func TestStaleHint_OrderOnStderr(t *testing.T) {
	t.Parallel()
	h := newHarness(t, erring("flaky", 1, errors.New("boom")))
	withStaleData(h)
	path := removeDefaultConfig(t, h)
	if code := h.exec("example.com"); code != 7 {
		t.Fatalf("exit %d, want 7: %s", code, h.stderr.String())
	}
	lines := strings.Split(h.stderr.String(), "\n")
	noConfig := slices.Index(lines, strings.TrimSuffix("hint: no config file at "+path+"; run nyx setup to store API keys and settings", "\n"))
	spam, ipapi := slices.Index(lines, staleSpamhausHint), slices.Index(lines, staleIpapiHint)
	firstError := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "error: ") })
	if noConfig < 0 || spam < 0 || ipapi < 0 || firstError < 0 {
		t.Fatalf("stderr lacks a line (no-config %d, Spamhaus %d, ipapi.is %d, error %d):\n%s", noConfig, spam, ipapi, firstError, h.stderr.String())
	}
	if noConfig >= min(spam, ipapi) || max(spam, ipapi) >= firstError {
		t.Errorf("the order is not no-config hint, stale hints, error:\n%s", h.stderr.String())
	}
}

// A source is not stale while its last successful check is recent, or once its copy in use is
// recent: a recorded response alone is not a check.
func TestStaleHint_ARecentCheckOrCopyHidesIt(t *testing.T) {
	t.Parallel()
	recent := func(h *harness) string { return h.now.Add(-24 * time.Hour).Format(time.RFC3339) }
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, h *harness)
		want  []string
	}{
		{"nothing recorded", func(*testing.T, *harness) {}, []string{staleSpamhausHint, staleIpapiHint}},
		{"Spamhaus checked yesterday", func(t *testing.T, h *harness) {
			writeThreatFile(t, h, "spamhaus.state.json", `{"last_response":"`+recent(h)+`","last_checked":"`+recent(h)+`"}`)
		}, []string{staleIpapiHint}},
		{"ipapi.is checked yesterday", func(t *testing.T, h *harness) {
			writeThreatFile(t, h, "ipapi.state.json", `{"last_response":"`+recent(h)+`","last_checked":"`+recent(h)+`"}`)
		}, []string{staleSpamhausHint}},
		{"both answered yesterday, never checked", func(t *testing.T, h *harness) {
			writeThreatFile(t, h, "spamhaus.state.json", `{"last_response":"`+recent(h)+`","last_checked":null}`)
			writeThreatFile(t, h, "ipapi.state.json", `{"last_response":"`+recent(h)+`","last_checked":null}`)
		}, []string{staleSpamhausHint, staleIpapiHint}},
		{"a recent downloaded Spamhaus copy", func(t *testing.T, h *harness) {
			writeDownloadedDrop(t, h, downloadedAt, nil, nil)
		}, []string{staleIpapiHint}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, noop())
			withStaleData(h)
			c.setup(t, h)
			if code := h.exec("example.com"); code != 0 {
				t.Fatalf("exit %d: %s", code, h.stderr.String())
			}
			if got := staleHintLines(h); !sameSet(got, c.want) {
				t.Errorf("hint lines %q, want %q\nstderr:\n%s", got, c.want, h.stderr.String())
			}
		})
	}
}
