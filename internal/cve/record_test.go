package cve

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadEntry decodes the NVD entry in testdata/name.
func loadEntry(t *testing.T, name string) *Entry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return &e
}

// encode is v as the envelope writes it: compact, without HTML escaping.
func encode(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
}

const (
	noScore = `"cvss_version":null,"cvss_score":null,"cvss_severity":null,"cvss_vector":null,"cvss_source":null`
	log4j   = `"id":"CVE-2021-44228","status":"Analyzed","published":"2021-12-10T10:15:09Z","last_modified":"2025-10-27T17:40:33Z",` +
		`"description":"Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."`
)

// fixtureRecords is each fixture's record exactly as --json writes it: every
// key, in order, null or [] when empty.
var fixtureRecords = map[string]string{
	// A rejected CVE is a record, not a not-found; with no metrics every cvss_* key is null.
	"rejected.json": `{"id":"CVE-2021-0001","status":"Rejected","published":"2021-05-01T00:00:00Z","last_modified":"2023-11-07T03:28:00Z",` +
		`"description":"Rejected reason: DO NOT USE THIS CANDIDATE NUMBER.",` + noScore + `,"weaknesses":[],"affected_products":[],"references":[]}`,
	// Zoneless timestamps are UTC, to the second; Primary beats Secondary within a version.
	"primary-over-secondary.json": `{` + log4j + `,"cvss_version":"3.1","cvss_score":10,"cvss_severity":"CRITICAL",` +
		`"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss_source":"nvd@nist.gov","weaknesses":[],"affected_products":[],"references":[]}`,
	// A Secondary 4.0 beats a Primary 3.1: the version outranks the source.
	"secondary-v40-over-primary-v31.json": `{"id":"CVE-2024-0001","status":"Analyzed","published":"2024-03-01T12:00:00Z","last_modified":"2024-03-02T12:00:00Z",` +
		`"description":"An example vulnerability scored by its CNA under CVSS 4.0.","cvss_version":"4.0","cvss_score":9.3,"cvss_severity":"CRITICAL",` +
		`"cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N","cvss_source":"cna@example.com","weaknesses":[],"affected_products":[],"references":[]}`,
	// A v2-only score takes its severity from the metric.
	"only-v2.json": `{"id":"CVE-2014-0160","status":"Modified","published":"2014-04-07T22:55:03Z","last_modified":"2025-04-12T10:46:40Z",` +
		`"description":"The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets.",` +
		`"cvss_version":"2.0","cvss_score":5,"cvss_severity":"MEDIUM","cvss_vector":"AV:N/AC:L/Au:N/C:P/I:N/A:N","cvss_source":"nvd@nist.gov",` +
		`"weaknesses":[],"affected_products":[],"references":[]}`,
	// CPE escapes are removed from vendor, product and version, and kept in the CPE.
	"cpe-escapes.json": `{"id":"CVE-2020-0001","status":"Analyzed","published":"2020-01-01T00:00:00Z","last_modified":"2020-01-02T00:00:00Z",` +
		`"description":"An example vulnerability in a product whose CPE needs escaping.",` + noScore + `,"weaknesses":[],"affected_products":[` +
		`{"cpe":"cpe:2.3:a:acme\\:labs:widget\\_pro\\!:1.0\\.2:*:*:*:*:*:*:*","vendor":"acme:labs","product":"widget_pro!","version":"1.0.2",` +
		`"version_start_including":null,"version_start_excluding":null,"version_end_including":null,"version_end_excluding":null}],"references":[]}`,
	// Nested configuration nodes: vulnerable matches only, - as null.
	"nested-nodes.json": `{` + log4j + `,` + noScore + `,"weaknesses":[],"affected_products":[` +
		`{"cpe":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","vendor":"apache","product":"log4j","version":null,` +
		`"version_start_including":"2.0.1","version_start_excluding":null,"version_end_including":null,"version_end_excluding":"2.3.1"},` +
		`{"cpe":"cpe:2.3:a:siemens:sppa-t3000_ses3000_firmware:-:*:*:*:*:*:*:*","vendor":"siemens","product":"sppa-t3000_ses3000_firmware","version":null,` +
		`"version_start_including":null,"version_start_excluding":null,"version_end_including":null,"version_end_excluding":null}],"references":[]}`,
	// A duplicate CPE match is kept once; different bounds are not a duplicate.
	"duplicate-cpe.json": `{` + log4j + `,` + noScore + `,"weaknesses":[],"affected_products":[` +
		`{"cpe":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","vendor":"apache","product":"log4j","version":null,` +
		`"version_start_including":"2.13.0","version_start_excluding":null,"version_end_including":null,"version_end_excluding":"2.15.0"},` +
		`{"cpe":"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*","vendor":"apache","product":"log4j","version":null,` +
		`"version_start_including":"2.4.0","version_start_excluding":null,"version_end_including":null,"version_end_excluding":"2.12.2"}],"references":[]}`,
	// References with their tags, [] when the NVD has none; a URL's & is written as it is.
	"references.json": `{` + log4j + `,` + noScore + `,"weaknesses":[],"affected_products":[],"references":[` +
		`{"url":"https://logging.apache.org/log4j/2.x/security.html?a=1&b=2","tags":["Vendor Advisory","Patch"]},` +
		`{"url":"https://example.com/writeup","tags":[]}]}`,
	// English weaknesses, de-duplicated in order.
	"weaknesses.json": `{` + log4j + `,` + noScore + `,"weaknesses":["CWE-502","CWE-400","CWE-917"],"affected_products":[],"references":[]}`,
	// The English description among others, trimmed.
	"english-among-others.json": `{"id":"CVE-2023-0002","status":"Analyzed","published":"2023-02-01T00:00:00Z","last_modified":"2023-02-02T00:00:00Z",` +
		`"description":"An example vulnerability.",` + noScore + `,"weaknesses":[],"affected_products":[],"references":[]}`,
	// No English description: the first of any language.
	"non-english-description.json": `{"id":"CVE-2023-0001","status":"Awaiting Analysis","published":"2023-01-01T00:00:00Z","last_modified":"2023-01-02T00:00:00Z",` +
		`"description":"Una vulnerabilidad de ejemplo.",` + noScore + `,"weaknesses":[],"affected_products":[],"references":[]}`,
}

func TestFromNVD_EachFixture(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(fixtureRecords) {
		t.Errorf("%d fixtures, %d expected records", len(entries), len(fixtureRecords))
	}
	for name, want := range fixtureRecords {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := FromNVD(loadEntry(t, name))
			if got := encode(t, rec); got != want {
				t.Errorf("record\n got %s\nwant %s", got, want)
			}
			// The envelope writes the record through the field table: all of it is the same bytes.
			all, _ := Select("all")
			if got := encode(t, all.Project(rec)); got != want {
				t.Errorf("projected record\n got %s\nwant %s", got, want)
			}
		})
	}
}

// An entry that is empty, with timestamps the NVD never writes, still has every key.
func TestFromNVD_Empty(t *testing.T) {
	t.Parallel()
	got := encode(t, FromNVD(&Entry{ID: "CVE-2026-0001", Published: "yesterday"}))
	want := `{"id":"CVE-2026-0001","status":"","published":null,"last_modified":null,"description":null,` + noScore +
		`,"weaknesses":[],"affected_products":[],"references":[]}`
	if got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}

func TestNormaliseID(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]struct {
		id string
		ok bool
	}{
		"CVE-2021-44228":          {"CVE-2021-44228", true},
		" cve-2021-44228 ":        {"CVE-2021-44228", true},
		"CVE-2021-1234567890123":  {"CVE-2021-1234567890123", true},
		"CVE-0999-1234":           {"CVE-0999-1234", true},
		"CVE-2021-123":            {"CVE-2021-123", false},
		"CVE-21-1234":             {"CVE-21-1234", false},
		"2021-44228":              {"2021-44228", false},
		"CVE-2021-44228x":         {"CVE-2021-44228X", false},
		"":                        {"", false},
		"CVE-2021-44228\nCVE-202": {"CVE-2021-44228\nCVE-202", false},
	} {
		if id, ok := NormaliseID(in); id != want.id || ok != want.ok {
			t.Errorf("NormaliseID(%q) = %q, %v; want %q, %v", in, id, ok, want.id, want.ok)
		}
	}
}
