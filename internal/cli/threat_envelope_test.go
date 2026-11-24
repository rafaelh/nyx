package cli_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// The update's --json envelope is a stable interface: every key is present on exit 0 and exit 7,
// whatever the outcome.

var (
	tdEnvelopeKeys = []string{"data", "meta"}
	tdDataKeys     = []string{"lists", "sources"}
	tdMetaKeys     = []string{"errors", "hint", "warnings"}
	tdSourceKeys   = []string{"copyright", "error", "last_contacted", "next_update", "outcome", "source", "terms"}
	tdListKeys     = []string{"added", "entries", "list", "new_updated", "old_entries", "old_updated", "removed", "source"}
	tdErrorKeys    = []string{"error", "code", "hint", "input", "transient"}
	rfc3339UTC     = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)
	dateOnly       = regexp.MustCompile(`^\d{4}-\d\d-\d\d$`)
)

// sortedKeys is the keys of the JSON object raw, sorted.
func sortedKeys(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	return slices.Sorted(slices.Values(keysOf(t, raw)))
}

// checkThreatKeys checks every key of the envelope on stdout, at each level.
func checkThreatKeys(t *testing.T, h *harness) {
	t.Helper()
	raw := json.RawMessage(h.stdout.String())
	if got := sortedKeys(t, raw); !slices.Equal(got, tdEnvelopeKeys) {
		t.Fatalf("envelope keys %v, want %v", got, tdEnvelopeKeys)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
		Meta json.RawMessage `json:"meta"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if got := sortedKeys(t, env.Data); !slices.Equal(got, tdDataKeys) {
		t.Errorf("data keys %v, want %v", got, tdDataKeys)
	}
	if got := sortedKeys(t, env.Meta); !slices.Equal(got, tdMetaKeys) {
		t.Errorf("meta keys %v, want %v", got, tdMetaKeys)
	}
	var data struct {
		Sources []json.RawMessage `json:"sources"`
		Lists   []json.RawMessage `json:"lists"`
	}
	var meta struct {
		Errors   []json.RawMessage `json:"errors"`
		Warnings []string          `json:"warnings"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(env.Meta, &meta); err != nil {
		t.Fatal(err)
	}
	if len(data.Sources) != 2 || len(data.Lists) != 5 {
		t.Errorf("%d sources and %d lists, want 2 and 5", len(data.Sources), len(data.Lists))
	}
	for _, s := range data.Sources {
		if got := sortedKeys(t, s); !slices.Equal(got, tdSourceKeys) {
			t.Errorf("source keys %v, want %v: %s", got, tdSourceKeys, s)
		}
		var withErr struct {
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(s, &withErr); err != nil {
			t.Fatal(err)
		}
		if string(withErr.Error) != "null" {
			if got := keysOf(t, withErr.Error); !slices.Equal(got, tdErrorKeys) {
				t.Errorf("a source's error keys %v, want %v", got, tdErrorKeys)
			}
		}
	}
	for _, l := range data.Lists {
		if got := sortedKeys(t, l); !slices.Equal(got, tdListKeys) {
			t.Errorf("list keys %v, want %v: %s", got, tdListKeys, l)
		}
	}
	if meta.Errors == nil || meta.Warnings == nil {
		t.Errorf("meta.errors or meta.warnings is not a list: %s", env.Meta)
	}
	for _, e := range meta.Errors {
		if got := keysOf(t, e); !slices.Equal(got, tdErrorKeys) {
			t.Errorf("meta.errors entry keys %v, want %v", got, tdErrorKeys)
		}
	}
}

// checkThreatListDates verifies source-specific UTC timestamp/day formatting.
func checkThreatListDates(t *testing.T, env threatEnvelope) {
	t.Helper()
	if got := len(env.Data.Lists); got != len(tdListNames) {
		t.Fatalf("%d lists, want %d", got, len(tdListNames))
	}
	for i, l := range env.Data.Lists {
		if l.List != tdListNames[i] || l.Source != tdSourceOf[l.List] {
			t.Errorf("list %d is %s of %s, want %s of %s", i, l.List, l.Source, tdListNames[i], tdSourceOf[tdListNames[i]])
		}
		re := dateOnly
		if l.Source == threatdata.Spamhaus {
			re = rfc3339UTC
		}
		if !re.MatchString(l.OldUpdated) || !re.MatchString(l.NewUpdated) {
			t.Errorf("%s's dates %q and %q are not written as %s dates them", l.List, l.OldUpdated, l.NewUpdated, l.Source)
		}
	}
}

// On exit 0: Spamhaus updated, ipapi.is already current.
func TestThreatEnvelope_KeysOnSuccess(t *testing.T) {
	t.Parallel()
	w := newThreatWorld(t)
	w.serveIpapi(w.d0, 0)
	if code := w.update("--json"); code != 0 {
		t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
	}
	if w.h.stderr.Len() != 0 {
		t.Errorf("stderr %q on exit 0", w.h.stderr.String())
	}
	checkThreatKeys(t, w.h)
	env := w.h.threatEnvelope()
	checkThreatListDates(t, env)
	if got := []string{env.Data.Sources[0].Source, env.Data.Sources[1].Source}; !slices.Equal(got, []string{threatdata.Spamhaus, threatdata.Ipapi}) {
		t.Errorf("sources %v, want spamhaus then ipapi.is", got)
	}
	now := tdStamp(w.h.now)

	sh := env.source(t, threatdata.Spamhaus)
	if sh.Outcome != "updated" || tdStr(sh.LastContacted) != now || sh.NextUpdate != nil || sh.Error != nil {
		t.Errorf("spamhaus %+v: want updated, last contacted %s, no next_update, no error", sh, now)
	}
	if tdStr(sh.Copyright) != tdCopyright || tdStr(sh.Terms) != tdTerms {
		t.Errorf("spamhaus's credit %s, %s; want %q, %q", tdStr(sh.Copyright), tdStr(sh.Terms), tdCopyright, tdTerms)
	}
	ip := env.source(t, threatdata.Ipapi)
	if ip.Outcome != "current" || tdStr(ip.LastContacted) != now || ip.NextUpdate != nil || ip.Error != nil {
		t.Errorf("ipapi.is %+v: want current, last contacted %s, no next_update, no error", ip, now)
	}
	if ip.Copyright != nil || ip.Terms != nil {
		t.Errorf("ipapi.is carries a credit: %s, %s", tdStr(ip.Copyright), tdStr(ip.Terms))
	}

	for _, name := range []string{spamhaus.ListV4, spamhaus.ListV6, spamhaus.ListASN} {
		l := env.list(t, name)
		n := 80
		if name != spamhaus.ListV4 {
			n = 20
		}
		want := threatListOut{List: name, Source: threatdata.Spamhaus, OldUpdated: tdStamp(w.d0), NewUpdated: tdStamp(w.d2),
			OldEntries: n, Entries: n, Added: 5, Removed: 5}
		if l != want {
			t.Errorf("%s\n got %+v\nwant %+v", name, l, want)
		}
	}
	for name, n := range map[string]int{threatdata.ListNetworks: 80, threatdata.ListASNs: 20} {
		l := env.list(t, name)
		want := threatListOut{List: name, Source: threatdata.Ipapi, OldUpdated: tdDay(w.d0), NewUpdated: tdDay(w.d0),
			OldEntries: n, Entries: n}
		if l != want {
			t.Errorf("%s\n got %+v\nwant %+v", name, l, want)
		}
	}
	if len(env.Meta.Errors) != 0 || len(env.Meta.Warnings) != 0 || env.Meta.Hint != nil {
		t.Errorf("meta %+v, want no errors, no warnings and a null hint", env.Meta)
	}
}

// On exit 7: Spamhaus failed after a response, ipapi.is skipped.
func TestThreatEnvelope_KeysOnAPartialResult(t *testing.T) {
	t.Parallel()
	w := newThreatWorld(t)
	w.fail(threatdata.Spamhaus, http.StatusInternalServerError)
	w.skipped(threatdata.Ipapi)
	if code := w.update("--json"); code != 7 {
		t.Fatalf("exit %d, want 7\nstderr %s", code, w.h.stderr.String())
	}
	checkThreatKeys(t, w.h)
	env := w.h.threatEnvelope()
	checkThreatListDates(t, env)
	now := w.h.now

	sh := env.source(t, threatdata.Spamhaus)
	if sh.Outcome != "failed" || tdStr(sh.LastContacted) != tdStamp(now) || tdStr(sh.NextUpdate) != tdStamp(now.Add(time.Hour)) {
		t.Errorf("spamhaus %+v: want failed, last contacted %s, next update %s", sh, tdStamp(now), tdStamp(now.Add(time.Hour)))
	}
	if sh.Error == nil || sh.Error.Code != "UPSTREAM_ERROR" || !strings.Contains(sh.Error.Error, "HTTP 500") || sh.Error.Transient {
		t.Errorf("spamhaus's error %+v, want UPSTREAM_ERROR for HTTP 500, not transient", sh.Error)
	}
	if tdStr(sh.Copyright) != tdCopyright || tdStr(sh.Terms) != tdTerms {
		t.Errorf("spamhaus's credit %s, %s; want the built-in copy's", tdStr(sh.Copyright), tdStr(sh.Terms))
	}
	ip := env.source(t, threatdata.Ipapi)
	last := now.Add(-10 * time.Minute)
	if ip.Outcome != "skipped" || tdStr(ip.LastContacted) != tdStamp(last) || tdStr(ip.NextUpdate) != tdStamp(last.Add(time.Hour)) || ip.Error != nil {
		t.Errorf("ipapi.is %+v: want skipped, last contacted %s, next update %s, no error", ip, tdStamp(last), tdStamp(last.Add(time.Hour)))
	}
	if ip.Copyright != nil || ip.Terms != nil {
		t.Errorf("ipapi.is carries a credit: %s, %s", tdStr(ip.Copyright), tdStr(ip.Terms))
	}
	for _, l := range env.Data.Lists {
		if l.OldUpdated != l.NewUpdated || l.OldEntries != l.Entries || l.Added != 0 || l.Removed != 0 {
			t.Errorf("%s was not replaced, yet %+v", l.List, l)
		}
	}
	if len(env.Meta.Errors) != 1 || env.Meta.Errors[0].Code != "UPSTREAM_ERROR" {
		t.Errorf("meta.errors %+v, want Spamhaus's error alone", env.Meta.Errors)
	}
	if f := w.h.theError(true); f.code != "PARTIAL" {
		t.Errorf("stderr's error %+v, want PARTIAL", f)
	}
}

// Exit 1 writes no envelope.
func TestThreatEnvelope_NoneOnExitOne(t *testing.T) {
	t.Parallel()
	w := newThreatWorld(t)
	w.fail(threatdata.Spamhaus, http.StatusInternalServerError)
	w.fail(threatdata.Ipapi, http.StatusInternalServerError)
	f := w.h.failed(w.update("--json"), 1, true)
	if f.code != "UPSTREAM_ERROR" {
		t.Errorf("error %+v, want UPSTREAM_ERROR", f)
	}
}
