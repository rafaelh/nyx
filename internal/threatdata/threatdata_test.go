package threatdata_test

import (
	"bytes"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/threatdata"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
)

// The update's two hosts, which tests elsewhere check nothing else contacts.
func TestHosts(t *testing.T) {
	t.Parallel()
	if threatdata.SpamhausHost != "www.spamhaus.org" || threatdata.IpapiHost != "ipapi.is" {
		t.Errorf("hosts = %q and %q, want www.spamhaus.org and ipapi.is", threatdata.SpamhausHost, threatdata.IpapiHost)
	}
	if threatdata.Spamhaus != "spamhaus" || threatdata.Ipapi != "ipapi.is" {
		t.Errorf("sources = %q and %q, want spamhaus and ipapi.is", threatdata.Spamhaus, threatdata.Ipapi)
	}
}

// The directory is threat-data beside the default config file: under $XDG_CONFIG_HOME/nyx, else
// ~/.config/nyx, else nowhere.
func TestDir(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		env  config.Env
		want string
	}{
		{"XDG_CONFIG_HOME first", config.Env{"HOME=/home/u", "XDG_CONFIG_HOME=/x/config"}, filepath.Join("/x/config", "nyx", "threat-data")},
		{"XDG_CONFIG_HOME alone", config.Env{"XDG_CONFIG_HOME=/x/config"}, filepath.Join("/x/config", "nyx", "threat-data")},
		{"else HOME", config.Env{"HOME=/home/u"}, filepath.Join("/home/u", ".config", "nyx", "threat-data")},
		{"an empty XDG_CONFIG_HOME is unset", config.Env{"XDG_CONFIG_HOME=", "HOME=/home/u"}, filepath.Join("/home/u", ".config", "nyx", "threat-data")},
		{"neither", config.Env{"PATH=/bin"}, ""},
		{"no environment", nil, ""},
	} {
		if got := threatdata.Dir(c.env); got != c.want {
			t.Errorf("%s: Dir = %q, want %q", c.name, got, c.want)
		}
	}
}

// With no downloaded copy, the lists in use are the built-in ones, described in order.
func TestLoad_BuiltInWhenNothingIsDownloaded(t *testing.T) {
	t.Parallel()
	b := builtIn(t, stdSpamhaus(), stdIpapi())
	for _, dir := range []string{t.TempDir(), filepath.Join(t.TempDir(), "absent"), ""} {
		s := b.Load(dir, now)
		want := []threatdata.List{
			{Source: threatdata.Spamhaus, Name: spamhaus.ListV4, Updated: stamp(d0), Entries: 80},
			{Source: threatdata.Spamhaus, Name: spamhaus.ListV6, Updated: stamp(d0), Entries: 20},
			{Source: threatdata.Spamhaus, Name: spamhaus.ListASN, Updated: stamp(d0), Entries: 20},
			{Source: threatdata.Ipapi, Name: threatdata.ListNetworks, Updated: day(d0), Entries: 80},
			{Source: threatdata.Ipapi, Name: threatdata.ListASNs, Updated: day(d0), Entries: 20},
		}
		if !slices.Equal(s.Lists, want) {
			t.Errorf("dir %q: lists\n%+v\nwant\n%+v", dir, s.Lists, want)
		}
		if len(s.Warnings) != 0 || len(s.Stale) != 0 {
			t.Errorf("dir %q: warnings %v, stale %v; want none", dir, s.Warnings, s.Stale)
		}
		if got := s.Drop.Networks(v4Addr(3)); len(got) != 1 {
			t.Errorf("dir %q: the built-in drop_v4 matched %v", dir, got)
		}
		if s.Abusive == nil {
			t.Errorf("dir %q: no ipapi.is lists to match", dir)
		} else if got := s.Abusive.ASN(ipapiASN(3)); len(got) != 1 {
			t.Errorf("dir %q: the built-in asns matched %v", dir, got)
		}
		if s.Copyright != copyright || s.Terms != terms {
			t.Errorf("dir %q: credit %q, %q; want the built-in drop_v4's", dir, s.Copyright, s.Terms)
		}
	}
}

// With no directory, nothing is read, nothing is ever stale, and nothing warns, however old the
// built-in copies are.
func TestLoad_NoDirectory(t *testing.T) {
	t.Parallel()
	s := builtIn(t, stdSpamhaus(), stdIpapi()).Load("", now.AddDate(2, 0, 0))
	if len(s.Lists) != 5 {
		t.Fatalf("lists %+v, want five", s.Lists)
	}
	if len(s.Warnings) != 0 || len(s.Stale) != 0 {
		t.Errorf("warnings %v, stale %v; want none", s.Warnings, s.Stale)
	}
}

// A nil *BuiltIn uses the copies embedded in the binary.
func TestLoad_TheEmbeddedCopies(t *testing.T) {
	t.Parallel()
	embedded, err := spamhaus.ParseBundle(spamhaus.Builtin())
	if err != nil {
		t.Fatalf("the embedded Spamhaus bundle: %v", err)
	}
	ip := abusive.Default()
	want := []threatdata.List{
		{Source: threatdata.Spamhaus, Name: spamhaus.ListV4, Updated: embedded.V4.Meta.Updated(), Entries: len(embedded.V4.Entries)},
		{Source: threatdata.Spamhaus, Name: spamhaus.ListV6, Updated: embedded.V6.Meta.Updated(), Entries: len(embedded.V6.Entries)},
		{Source: threatdata.Spamhaus, Name: spamhaus.ListASN, Updated: embedded.ASNs.Meta.Updated(), Entries: len(embedded.ASNs.Entries)},
		{Source: threatdata.Ipapi, Name: threatdata.ListNetworks, Updated: ip.Nets.Updated, Entries: len(ip.Nets.Entries)},
		{Source: threatdata.Ipapi, Name: threatdata.ListASNs, Updated: ip.ASNs.Updated, Entries: len(ip.ASNs.Entries)},
	}
	for name, s := range map[string]threatdata.Set{
		"no directory": (*threatdata.BuiltIn)(nil).Load("", now),
		"an empty one": (*threatdata.BuiltIn)(nil).Load(t.TempDir(), now),
	} {
		if !slices.Equal(s.Lists, want) {
			t.Errorf("%s: lists\n%+v\nwant\n%+v", name, s.Lists, want)
		}
		if len(s.Lists) > 0 && s.Lists[0].Entries == 0 {
			t.Errorf("%s: the embedded drop_v4 is empty", name)
		}
	}
}

// Select copies per list, preferring downloaded data on equal dates, so a source can mix
// versions.
func TestLoad_Precedence(t *testing.T) {
	t.Parallel()
	b := builtIn(t, stdSpamhaus(), stdIpapi())
	dir := t.TempDir()
	older := d0.AddDate(0, 0, -1)
	writeFile(t, dir, spamhausFile, bundle(
		dropFile(v4Row, d1, 100, 81),    // newer: downloaded
		dropFile(v6Row, older, 100, 21), // older: built in
		dropFile(asnRow, d0, 100, 22),   // the same date: downloaded
	), 0o600)
	writeFile(t, dir, ipapiData, ipapiFile(t, snapshot(day(d1), 100, 83, day(older), 100, 24)), 0o600)

	s := b.Load(dir, now)
	want := []threatdata.List{
		{Source: threatdata.Spamhaus, Name: spamhaus.ListV4, Updated: stamp(d1), Entries: 81, Downloaded: true},
		{Source: threatdata.Spamhaus, Name: spamhaus.ListV6, Updated: stamp(d0), Entries: 20},
		{Source: threatdata.Spamhaus, Name: spamhaus.ListASN, Updated: stamp(d0), Entries: 22, Downloaded: true},
		{Source: threatdata.Ipapi, Name: threatdata.ListNetworks, Updated: day(d1), Entries: 83, Downloaded: true},
		{Source: threatdata.Ipapi, Name: threatdata.ListASNs, Updated: day(d0), Entries: 20},
	}
	if !slices.Equal(s.Lists, want) {
		t.Errorf("lists\n%+v\nwant\n%+v", s.Lists, want)
	}
	if len(s.Warnings) != 0 {
		t.Errorf("warnings %v, want none", s.Warnings)
	}
	// Matching must use the selected active data.
	for _, c := range []struct {
		what  string
		got   int
		match bool
	}{
		{"a downloaded drop_v4 entry", len(s.Drop.Networks(v4Addr(100))), true},
		{"a built-in drop_v4 entry", len(s.Drop.Networks(v4Addr(0))), false},
		{"a built-in drop_v6 entry", len(s.Drop.Networks(v6Addr(0))), true},
		{"a downloaded drop_v6 entry", len(s.Drop.Networks(v6Addr(100))), false},
		{"a downloaded asndrop entry", len(s.Drop.ASN(asnOf(100))), true},
		{"a built-in asndrop entry", len(s.Drop.ASN(asnOf(0))), false},
	} {
		if (c.got > 0) != c.match {
			t.Errorf("%s: %d matches, want match=%v", c.what, c.got, c.match)
		}
	}
	if s.Abusive == nil {
		t.Fatal("no ipapi.is lists to match")
	}
	if len(s.Abusive.Networks(netAddr(100))) != 1 || len(s.Abusive.Networks(netAddr(0))) != 0 {
		t.Errorf("networks: the downloaded entry matched %v and the built-in one %v; want only the downloaded one",
			s.Abusive.Networks(netAddr(100)), s.Abusive.Networks(netAddr(0)))
	}
	if len(s.Abusive.ASN(ipapiASN(0))) != 1 || len(s.Abusive.ASN(ipapiASN(100))) != 0 {
		t.Errorf("asns: the built-in entry matched %v and the downloaded one %v; want only the built-in one",
			s.Abusive.ASN(ipapiASN(0)), s.Abusive.ASN(ipapiASN(100)))
	}

	// A list of the same date as the built-in one is the downloaded one.
	same := t.TempDir()
	writeFile(t, same, spamhausFile, bundle(dropFile(v4Row, d0, 100, 81), dropFile(v6Row, d0, 100, 21), dropFile(asnRow, d0, 100, 22)), 0o600)
	writeFile(t, same, ipapiData, ipapiFile(t, snapshot(day(d0), 100, 83, day(d0), 100, 24)), 0o600)
	s = b.Load(same, now)
	for name, n := range map[string]int{spamhaus.ListV4: 81, spamhaus.ListV6: 21, spamhaus.ListASN: 22} {
		if got := inUse(t, s, name); !got.Downloaded || got.Entries != n {
			t.Errorf("%s of the same date: %+v, want the downloaded copy", name, got)
		}
	}
	if got := inUse(t, s, threatdata.ListNetworks); !got.Downloaded || got.Entries != 83 {
		t.Errorf("networks of the same date: %+v, want the downloaded copy", got)
	}
	if got := inUse(t, s, threatdata.ListASNs); !got.Downloaded || got.Entries != 24 {
		t.Errorf("asns of the same date: %+v, want the downloaded copy", got)
	}
}

// Spamhaus's credit comes from the drop_v4 list in use, sanitised, and from the built-in copy when
// that list has none.
func TestLoad_Credit(t *testing.T) {
	t.Parallel()
	b := builtIn(t, stdSpamhaus(), stdIpapi())
	rawCopyright := "(c) 2027 The Spamhaus Project SLU\u202e"
	withCredit := file(append(rows(v4Row, 0, 80),
		strings.Replace(strings.Replace(metaLine(d1, 80), copyright, rawCopyright, 1), terms, "https://www.spamhaus.org/drop/terms/v2", 1))...)
	noCredit := file(append(rows(v4Row, 0, 80),
		`{"type":"metadata","timestamp":`+itoa(d1.Unix())+`,"size":1,"records":80}`)...)
	for _, c := range []struct {
		name            string
		v4              []byte
		copyright, term string
	}{
		{"the downloaded drop_v4's", withCredit, sanitize.Line(rawCopyright), "https://www.spamhaus.org/drop/terms/v2"},
		{"the built-in copy's when the downloaded drop_v4 has none", noCredit, copyright, terms},
	} {
		dir := t.TempDir()
		writeFile(t, dir, spamhausFile, bundle(c.v4, dropFile(v6Row, d0, 0, 20), dropFile(asnRow, d0, 0, 20)), 0o600)
		s := b.Load(dir, now)
		if !inUse(t, s, spamhaus.ListV4).Downloaded {
			t.Fatalf("%s: the downloaded drop_v4 is not in use", c.name)
		}
		if s.Copyright != c.copyright || s.Terms != c.term {
			t.Errorf("%s: credit %q, %q; want %q, %q", c.name, s.Copyright, s.Terms, c.copyright, c.term)
		}
	}
	// A downloaded drop_v4 that isn't in use gives no credit.
	dir := t.TempDir()
	older := bytes.Replace(withCredit, []byte(itoa(d1.Unix())), []byte(itoa(d0.AddDate(0, 0, -1).Unix())), 1)
	writeFile(t, dir, spamhausFile, bundle(older, dropFile(v6Row, d0, 0, 20), dropFile(asnRow, d0, 0, 20)), 0o600)
	if s := b.Load(dir, now); s.Copyright != copyright || s.Terms != terms {
		t.Errorf("with the built-in drop_v4 in use: credit %q, %q; want the built-in one", s.Copyright, s.Terms)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// checkWarning verifies exactly one source/path-specific unreadable-download notice.
func checkWarning(t *testing.T, name string, s threatdata.Set, source, dir string) {
	t.Helper()
	if len(s.Warnings) != 1 || s.Warnings[0].Source != source {
		t.Errorf("%s: warnings %+v, want one for %s", name, s.Warnings, source)
		return
	}
	text := s.Warnings[0].Text
	if !strings.HasPrefix(text, "the downloaded ") || !strings.Contains(strings.ToLower(text), source) ||
		!strings.Contains(text, " data in "+dir+" is unreadable (") ||
		!strings.HasSuffix(text, "), so nyx uses its built-in copy; run nyx setup --update-threat-data to replace it") {
		t.Errorf("%s: warning %q", name, text)
	}
	if strings.Contains(text, "unreadable ()") {
		t.Errorf("%s: the warning %q gives no reason", name, text)
	}
}

// One corrupt Spamhaus list rejects the whole downloaded bundle, including otherwise newer
// lists.
func TestLoad_UnreadableSpamhausCopy(t *testing.T) {
	t.Parallel()
	b := builtIn(t, stdSpamhaus(), stdIpapi())
	v4 := dropFile(v4Row, d1, 100, 80)
	v6 := dropFile(v6Row, d1, 100, 20)
	asn := dropFile(asnRow, d1, 100, 20)
	good := bundle(v4, v6, asn)
	withoutASN, _, found := bytes.Cut(good, []byte(`{"list":"asndrop"}`))
	if !found {
		t.Fatal("the bundle has no asndrop marker")
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"a row that doesn't parse", bundle(v4, file(append(append(rows(v6Row, 100, 20), `{"cidr":"2001:db8:ffff::/48","sblid":`), metaLine(d1, 21))...), asn)},
		{"a row without its CIDR", bundle(file(append(append(rows(v4Row, 100, 79), `{"sblid":"SBL1","rir":"arin"}`), metaLine(d1, 80))...), v6, asn)},
		{"a control character in a row", bundle(v4, v6, file(append(append(rows(asnRow, 100, 19), `{"asn":1,"rir":"arin","domain":"x.example","cc":"US","asname":"BAD\u0007"}`), metaLine(d1, 20))...))},
		{"a control character in the metadata", bundle(file(append(rows(v4Row, 100, 80), strings.Replace(metaLine(d1, 80), copyright, `(c) \u0007`, 1))...), v6, asn)},
		{"an entry listed twice", bundle(file(append(append(rows(v4Row, 100, 80), v4Row(100)), metaLine(d1, 81))...), v6, asn)},
		{"no final metadata row", bundle(v4, file(rows(v6Row, 100, 20)...), asn)},
		{"fewer than 90% of the records it states", bundle(v4, v6, file(append(rows(asnRow, 100, 20), metaLine(d1, 23))...))},
		{"a list missing from the bundle", withoutASN},
		{"cut short", good[:len(good)/2]},
		{"empty", []byte{}},
	}
	for _, c := range cases {
		dir := t.TempDir()
		writeFile(t, dir, spamhausFile, c.data, 0o600)
		s := b.Load(dir, now)
		for _, name := range spamhausLists() {
			if l := inUse(t, s, name); l.Downloaded || l.Updated != stamp(d0) {
				t.Errorf("%s: %s in use is %+v, want the built-in copy", c.name, name, l)
			}
		}
		if len(s.Drop.Networks(v4Addr(0))) != 1 || len(s.Drop.Networks(v4Addr(100))) != 0 {
			t.Errorf("%s: the built-in drop_v4 isn't the one matched", c.name)
		}
		checkWarning(t, c.name, s, threatdata.Spamhaus, dir)
		for _, name := range ipapiLists() {
			if l := inUse(t, s, name); l.Updated != day(d0) {
				t.Errorf("%s: %s in use is %+v; the other source is unaffected", c.name, name, l)
			}
		}
	}

	// An unknown field is ignored, and the copy is used.
	dir := t.TempDir()
	extra := file(append(append(rows(v4Row, 100, 79), `{"cidr":"10.250.0.0/24","sblid":"SBL9","rir":"arin","added":"2026-10-01"}`), metaLine(d1, 80))...)
	writeFile(t, dir, spamhausFile, bundle(extra, v6, asn), 0o600)
	s := b.Load(dir, now)
	if l := inUse(t, s, spamhaus.ListV4); !l.Downloaded || len(s.Warnings) != 0 {
		t.Errorf("a row with an unknown field: drop_v4 %+v, warnings %v; want the downloaded copy and no warning", l, s.Warnings)
	}
}

// Both ipapi lists need valid data/dates/counts or the entire source falls back with one
// warning.
func TestLoad_UnreadableIpapiCopy(t *testing.T) {
	t.Parallel()
	b := builtIn(t, stdSpamhaus(), stdIpapi())
	good := func() abusive.Snapshot { return snapshot(day(d1), 100, 80, day(d1), 100, 20) }
	edit := func(f func(*abusive.Snapshot)) []byte {
		s := good()
		f(&s)
		return ipapiFile(t, s)
	}
	noStated := bytes.Replace(ipapiFile(t, good()), []byte(`"stated":20,`), nil, 1)
	if bytes.Equal(noStated, ipapiFile(t, good())) {
		t.Fatal("the ASNs' stated count wasn't removed")
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"not JSON", []byte(`{"networks":`)},
		{"empty", []byte{}},
		{"a control character", edit(func(s *abusive.Snapshot) { s.ASNs.Entries[3].Org = "Bad\u0007Org" })},
		{"a network listed twice", edit(func(s *abusive.Snapshot) {
			s.Nets.Entries = slices.Insert(s.Nets.Entries, 5, s.Nets.Entries[5])
			s.Nets.Stated++
		})},
		{"an ASN listed twice", edit(func(s *abusive.Snapshot) {
			s.ASNs.Entries = slices.Insert(s.ASNs.Entries, 5, s.ASNs.Entries[5])
			s.ASNs.Stated++
		})},
		{"no date", edit(func(s *abusive.Snapshot) { s.Nets.Updated = "" })},
		{"no stated count", noStated},
		{"fewer than 90% of the entries it states", edit(func(s *abusive.Snapshot) { s.Nets.Stated = 90 })},
	}
	for _, c := range cases {
		dir := t.TempDir()
		writeFile(t, dir, ipapiData, c.data, 0o600)
		s := b.Load(dir, now)
		for _, name := range ipapiLists() {
			if l := inUse(t, s, name); l.Downloaded || l.Updated != day(d0) {
				t.Errorf("%s: %s in use is %+v, want the built-in copy", c.name, name, l)
			}
		}
		if s.Abusive == nil || len(s.Abusive.ASN(ipapiASN(0))) != 1 {
			t.Errorf("%s: the built-in asns aren't the ones matched", c.name)
		}
		checkWarning(t, c.name, s, threatdata.Ipapi, dir)
		for _, name := range spamhausLists() {
			if l := inUse(t, s, name); l.Updated != stamp(d0) {
				t.Errorf("%s: %s in use is %+v; the other source is unaffected", c.name, name, l)
			}
		}
	}

	// Unknown fields, which a newer nyx may write, are ignored, and the copy is used.
	dir := t.TempDir()
	withExtra := bytes.Replace(ipapiFile(t, good()), []byte(`"networks":{`), []byte(`"source":"ipapi.is","networks":{"fetched":"2026-10-14T00:00:00Z",`), 1)
	withExtra = bytes.Replace(withExtra, []byte(`"rank":101,`), []byte(`"rank":101,"country":"AU",`), 1)
	writeFile(t, dir, ipapiData, withExtra, 0o600)
	s := b.Load(dir, now)
	if l := inUse(t, s, threatdata.ListNetworks); !l.Downloaded || len(s.Warnings) != 0 {
		t.Errorf("unknown fields: networks %+v, warnings %v; want the downloaded copy and no warning", l, s.Warnings)
	}
}

// Load never reads a temporary file an interrupted update left behind.
func TestLoad_IgnoresTemporaryFiles(t *testing.T) {
	t.Parallel()
	b := builtIn(t, stdSpamhaus(), stdIpapi())
	dir := t.TempDir()
	newer := bundle(dropFile(v4Row, d1, 100, 80), dropFile(v6Row, d1, 100, 20), dropFile(asnRow, d1, 100, 20))
	writeFile(t, dir, ".spamhaus-x.tmp", newer, 0o600)
	writeFile(t, dir, ".spamhaus-123.tmp", newer[:len(newer)/2], 0o600)
	s := b.Load(dir, now)
	for _, l := range s.Lists {
		if l.Downloaded {
			t.Errorf("%s in use is %+v, want the built-in copy", l.Name, l)
		}
	}
	if len(s.Lists) != 5 || len(s.Warnings) != 0 {
		t.Errorf("lists %+v, warnings %v; want five built-in lists and no warning", s.Lists, s.Warnings)
	}
}

// aged is a built-in copy with the given dates.
func aged(t *testing.T, v4, v6, asn time.Time, nets, asns string) *threatdata.BuiltIn {
	t.Helper()
	return builtIn(t, lists{dropFile(v4Row, v4, 0, 80), dropFile(v6Row, v6, 0, 20), dropFile(asnRow, asn, 0, 20)},
		snapshot(nets, 0, 80, asns, 0, 20))
}

// Staleness requires both oldest active data and last successful check to exceed 30 days.
func TestLoad_Staleness(t *testing.T) {
	t.Parallel()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	const dayLen = 24 * time.Hour
	recent := ago(5 * dayLen)
	// The oldest Spamhaus list is drop_v6, at 23:30 UTC: its day is the 23:30's, in any zone.
	oldV6 := time.Date(2026, 9, 12, 23, 30, 0, 0, time.UTC)
	spamhausHint := "Spamhaus DROP data is from 2026-09-12; run nyx setup --update-threat-data"
	recentDay := day(recent)
	for _, c := range []struct {
		name         string
		v4, v6, asn  time.Time
		nets, asns   string
		lastResponse *time.Time
		lastChecked  *time.Time
		downloadedV6 time.Time // when set, a downloaded copy whose drop_v6 has this date
		at           time.Time
		stale        []threatdata.Notice
	}{
		{name: "old data, never checked", v4: ago(40 * dayLen), v6: oldV6, asn: ago(35 * dayLen), nets: recentDay, asns: recentDay, at: now,
			stale: []threatdata.Notice{{Source: threatdata.Spamhaus, Text: spamhausHint}}},
		{name: "old data, checked a day ago", v4: ago(40 * dayLen), v6: oldV6, asn: ago(35 * dayLen), nets: recentDay, asns: recentDay, at: now,
			lastChecked: new(ago(dayLen))},
		{name: "old data, checked 31 days ago", v4: ago(40 * dayLen), v6: oldV6, asn: ago(35 * dayLen), nets: recentDay, asns: recentDay, at: now,
			lastChecked: new(ago(31 * dayLen)), stale: []threatdata.Notice{{Source: threatdata.Spamhaus, Text: spamhausHint}}},
		{name: "old data, checked exactly 30 days ago", v4: ago(40 * dayLen), v6: oldV6, asn: ago(35 * dayLen), nets: recentDay, asns: recentDay, at: now,
			lastChecked: new(ago(30 * dayLen))},
		{name: "recent data, checked 31 days ago", v4: recent, v6: recent, asn: recent, nets: recentDay, asns: recentDay, at: now,
			lastChecked: new(ago(31 * dayLen))},
		{name: "recent data, never checked", v4: recent, v6: recent, asn: recent, nets: recentDay, asns: recentDay, at: now},
		{name: "the oldest list exactly 30 days old", v4: recent, v6: ago(30 * dayLen), asn: recent, nets: recentDay, asns: recentDay, at: now},
		{name: "the oldest list 30 days and a second old", v4: recent, v6: ago(30*dayLen + time.Second), asn: recent, nets: recentDay, asns: recentDay, at: now,
			stale: []threatdata.Notice{{Source: threatdata.Spamhaus, Text: "Spamhaus DROP data is from " + day(ago(30*dayLen+time.Second)) + "; run nyx setup --update-threat-data"}}},
		{name: "a response is not a successful check", v4: ago(40 * dayLen), v6: oldV6, asn: ago(35 * dayLen), nets: recentDay, asns: recentDay, at: now,
			lastResponse: new(ago(dayLen)), stale: []threatdata.Notice{{Source: threatdata.Spamhaus, Text: spamhausHint}}},
		{name: "the oldest list in use, not the oldest built-in one", v4: ago(40 * dayLen), v6: oldV6, asn: ago(35 * dayLen), nets: recentDay, asns: recentDay, at: now,
			downloadedV6: ago(2 * dayLen),
			stale:        []threatdata.Notice{{Source: threatdata.Spamhaus, Text: "Spamhaus DROP data is from " + day(ago(40*dayLen)) + "; run nyx setup --update-threat-data"}}},
		// An ipapi.is date is 00:00 UTC of its day.
		{name: "ipapi.is exactly 30 days after its day began", v4: recent, v6: recent, asn: recent, nets: "2026-09-20", asns: "2026-09-25",
			at: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)},
		{name: "ipapi.is 30 days and a second after its day began", v4: recent, v6: recent, asn: recent, nets: "2026-09-25", asns: "2026-09-20",
			at:    time.Date(2026, 10, 20, 0, 0, 1, 0, time.UTC),
			stale: []threatdata.Notice{{Source: threatdata.Ipapi, Text: "ipapi.is abuse data is from 2026-09-20; run nyx setup --update-threat-data"}}},
		{name: "both stale, Spamhaus first", v4: ago(40 * dayLen), v6: oldV6, asn: ago(35 * dayLen), nets: "2026-09-01", asns: "2026-09-02", at: now,
			stale: []threatdata.Notice{
				{Source: threatdata.Spamhaus, Text: spamhausHint},
				{Source: threatdata.Ipapi, Text: "ipapi.is abuse data is from 2026-09-01; run nyx setup --update-threat-data"},
			}},
	} {
		dir := t.TempDir()
		if c.lastResponse != nil || c.lastChecked != nil {
			writeState(t, dir, c.lastResponse, c.lastChecked)
		}
		if !c.downloadedV6.IsZero() {
			writeFile(t, dir, spamhausFile, bundle(dropFile(v4Row, c.v4, 0, 80), dropFile(v6Row, c.downloadedV6, 0, 20), dropFile(asnRow, c.asn, 0, 20)), 0o600)
		}
		s := aged(t, c.v4, c.v6, c.asn, c.nets, c.asns).Load(dir, c.at)
		if !slices.Equal(s.Stale, c.stale) {
			t.Errorf("%s: stale %+v, want %+v", c.name, s.Stale, c.stale)
		}
	}
}

// Updated/current results refresh the successful-check clock; failed/skipped results do not.
func TestLoad_StalenessAfterAnUpdate(t *testing.T) {
	t.Parallel()
	old := now.AddDate(0, 0, -60)
	oldList := lists{dropFile(v4Row, old, 0, 80), dropFile(v6Row, old, 0, 20), dropFile(asnRow, old, 0, 20)}
	setup := func(t *testing.T) *world {
		t.Helper()
		w := newWorld(t)
		w.builtIn = builtIn(t, oldList, snapshot(day(old), 0, 80, day(old), 0, 20))
		w.serveSpamhaus(oldList)
		w.serveIpapi(day(old), 80, 0, 80, day(old), 20, 0, 20)
		if s := w.load(now); len(s.Stale) != 2 {
			t.Fatalf("before the update: stale %+v, want both sources", s.Stale)
		}
		return w
	}

	// Already current: checked now, so not stale for 30 days.
	w := setup(t)
	r := w.update()
	if source(t, r, threatdata.Spamhaus).Outcome != threatdata.Current || source(t, r, threatdata.Ipapi).Outcome != threatdata.Current {
		t.Fatalf("the update: %+v, want both current", r.Sources)
	}
	if s := w.load(now.AddDate(0, 0, 30)); len(s.Stale) != 0 {
		t.Errorf("30 days after a check that found both current: stale %+v", s.Stale)
	}
	if s := w.load(now.AddDate(0, 0, 31)); len(s.Stale) != 2 {
		t.Errorf("31 days after it: stale %+v, want both sources", s.Stale)
	}

	// Updated: checked now too.
	w = setup(t)
	w.serveSpamhaus(lists{dropFile(v4Row, old.AddDate(0, 0, 1), 0, 80), dropFile(v6Row, old, 0, 20), dropFile(asnRow, old, 0, 20)})
	if got := source(t, w.update(), threatdata.Spamhaus).Outcome; got != threatdata.Updated {
		t.Fatalf("the update: Spamhaus %s, want updated", got)
	}
	if s := w.load(now.AddDate(0, 0, 29)); slices.ContainsFunc(s.Stale, func(n threatdata.Notice) bool { return n.Source == threatdata.Spamhaus }) {
		t.Errorf("29 days after Spamhaus was updated: stale %+v", s.Stale)
	}

	// Failed: still stale.
	w = setup(t)
	w.spamhaus.set(pathV4, reply{status: 500})
	w.ipapi.set(pathNetworks, reply{status: 500})
	r = w.update()
	if source(t, r, threatdata.Spamhaus).Outcome != threatdata.Failed {
		t.Fatalf("the update: %+v, want Spamhaus failed", r.Sources)
	}
	if s := w.load(now); len(s.Stale) != 2 {
		t.Errorf("after a failed update: stale %+v, want both sources", s.Stale)
	}

	// Skipped: still stale.
	w = setup(t)
	writeState(t, w.dir, new(now.Add(-10*time.Minute)), nil)
	if got := source(t, w.update(), threatdata.Spamhaus).Outcome; got != threatdata.Skipped {
		t.Fatalf("the update: Spamhaus %s, want skipped", got)
	}
	if s := w.load(now); !slices.ContainsFunc(s.Stale, func(n threatdata.Notice) bool { return n.Source == threatdata.Spamhaus }) {
		t.Errorf("after a skipped update: stale %+v, want Spamhaus", s.Stale)
	}
}
