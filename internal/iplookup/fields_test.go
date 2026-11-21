package iplookup

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
)

const defaultKeys = "address,hostnames,kind,asn,as_name,as_prefix,rdap_netblock,rdap_org,rdap_registry,ptr,provider,provider_class," +
	"geo_country,geo_city,internetdb_ports,internetdb_hostnames,internetdb_tags,internetdb_cpes,internetdb_vulns,reverse_ip,reverse_ip_count,failures"

const activeKeys = "address,hostnames,kind,asn,as_name,as_prefix,rdap_netblock,rdap_org,rdap_registry,ptr,provider,provider_class," +
	"geo_country,geo_city,internetdb_ports,internetdb_hostnames,internetdb_tags,internetdb_cpes,internetdb_vulns,reverse_ip,reverse_ip_count," +
	"not_contacted,ports,tls,web,failures"

func mustSelect(t *testing.T, spec string, active bool) Fields {
	t.Helper()
	f, unknown, misused := Select(spec, active)
	if unknown != nil || misused != nil {
		t.Fatalf("Select(%q, %v): unknown %v, active only %v", spec, active, unknown, misused)
	}
	return f
}

func TestFieldNames_AreTheKeysInOrder(t *testing.T) {
	t.Parallel()
	if got := strings.Join(FieldNames(false), ","); got != defaultKeys {
		t.Errorf("default keys\n got %s\nwant %s", got, defaultKeys)
	}
	if got := strings.Join(FieldNames(true), ","); got != activeKeys {
		t.Errorf("active keys\n got %s\nwant %s", got, activeKeys)
	}
	if got := strings.Join(ActiveFieldNames(), ","); got != "not_contacted,ports,tls,web" {
		t.Errorf("active only keys: %s", got)
	}
}

func TestValidFields(t *testing.T) {
	t.Parallel()
	got := ValidFields(false)
	if !strings.HasPrefix(got, "valid fields: asn, as_name,") || !strings.HasSuffix(got, "reverse_ip_count, or all") {
		t.Errorf("default hint: %s", got)
	}
	for _, always := range []string{"address", "hostnames", "kind", "failures", "not_contacted", "ports"} {
		if strings.Contains(": "+got+",", " "+always+",") {
			t.Errorf("default hint names %q: %s", always, got)
		}
	}
	if got := ValidFields(true); !strings.Contains(got, "reverse_ip_count, not_contacted, ports, tls, web, or all") {
		t.Errorf("active hint: %s", got)
	}
}

func TestSelect_Names(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		spec   string
		active bool
		want   string
	}{
		{"nothing selects only the always-present keys", "", false, "address,hostnames,kind,failures"},
		{"blank is nothing", " , ,", true, "address,hostnames,kind,failures"},
		{"one key", "asn", false, "address,hostnames,kind,asn,failures"},
		{"table order, whatever the order given", "geo_city, asn ,ptr", false, "address,hostnames,kind,asn,ptr,geo_city,failures"},
		{"a name twice", "asn,asn", false, "address,hostnames,kind,asn,failures"},
		{"an always-present key by name", "failures,address", false, "address,hostnames,kind,failures"},
		{"all, default", "all", false, defaultKeys},
		{"all, active", "all", true, activeKeys},
		{"all among others", "asn,all", false, defaultKeys},
		{"an active key under active", "web,not_contacted", true, "address,hostnames,kind,not_contacted,web,failures"},
	}
	for _, c := range cases {
		f, unknown, misused := Select(c.spec, c.active)
		if unknown != nil || misused != nil {
			t.Errorf("%s: unknown %v, active only %v", c.name, unknown, misused)
			continue
		}
		if got := strings.Join(f.Names(), ","); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
		if f.Active() != c.active {
			t.Errorf("%s: Active() = %v", c.name, f.Active())
		}
	}
}

func TestAllFields(t *testing.T) {
	t.Parallel()
	if got := strings.Join(AllFields(false).Names(), ","); got != defaultKeys {
		t.Errorf("default: %s", got)
	}
	if got := strings.Join(AllFields(true).Names(), ","); got != activeKeys {
		t.Errorf("active: %s", got)
	}
}

func TestSelect_Rejects(t *testing.T) {
	t.Parallel()
	f, unknown, misused := Select("asn,bogus, other ,ports", false)
	if !slices.Equal(unknown, []string{"bogus", "other"}) {
		t.Errorf("unknown %v, want the two names as given, in order", unknown)
	}
	if !slices.Equal(misused, []string{"ports"}) {
		t.Errorf("active only %v, want ports", misused)
	}
	if len(f.Names()) != 0 || f.Has("asn") || f.Has("address") {
		t.Errorf("a rejected selection is not empty: %v", f.Names())
	}
	_, unknown, misused = Select("web,tls,not_contacted,ports", false)
	if unknown != nil || !slices.Equal(misused, []string{"web", "tls", "not_contacted", "ports"}) {
		t.Errorf("active keys without --active: unknown %v, active only %v", unknown, misused)
	}
	_, unknown, misused = Select("ports,nope", true)
	if !slices.Equal(unknown, []string{"nope"}) || misused != nil {
		t.Errorf("under active: unknown %v, active only %v", unknown, misused)
	}
}

func sources(f Fields) string {
	var out []string
	for _, s := range f.Sources() {
		out = append(out, string(s))
	}
	return strings.Join(out, ",")
}

func TestFields_Needs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		spec    string
		active  bool
		sources string // Sources(), in order
		probe   bool
		tls     bool
		web     bool
		shared  bool
	}{
		{"nothing asks nothing", "", false, "", false, false, false, false},
		{"asn asks cymru only", "asn", false, "cymru", false, false, false, false},
		{"as_name", "as_name", false, "cymru", false, false, false, false},
		{"rdap keys", "rdap_org", false, "rdap", false, false, false, false},
		{"ptr", "ptr", false, "ptr", false, false, false, false},
		{"the provider needs the asn", "provider", false, "cymru", false, false, false, false},
		{"the class too", "provider_class", false, "cymru", false, false, false, false},
		{"geolocation", "geo_country", false, "ripestat", false, false, false, false},
		{"internetdb", "internetdb_tags", false, "internetdb", false, false, false, false},
		{"reverse ip needs the provider, so cymru, and hackertarget", "reverse_ip", false, "cymru,hackertarget", false, false, false, false},
		{"its count too", "reverse_ip_count", false, "cymru,hackertarget", false, false, false, false},
		{"all default keys", "all", false, "cymru,rdap,ptr,ripestat,internetdb,hackertarget", false, false, false, false},
		{"not_contacted needs only the shared check", "not_contacted", true, "cymru", false, false, false, true},
		{"ports alone scans, with no TLS or GET", "ports", true, "cymru,internetdb,probe", true, false, false, true},
		{"tls needs the scan", "tls", true, "cymru,internetdb,probe", true, true, false, true},
		{"web needs the scan", "web", true, "cymru,internetdb,probe", true, false, true, true},
		{"ports and not_contacted", "ports,not_contacted", true, "cymru,internetdb,probe", true, false, false, true},
		{"all under active", "all", true, "cymru,rdap,ptr,ripestat,internetdb,hackertarget,probe", true, true, true, true},
		{"the shared check runs under active whatever is selected", "geo_country", true, "cymru,ripestat", false, false, false, true},
		{"even with nothing selected", "", true, "cymru", false, false, false, true},
	}
	for _, c := range cases {
		f := mustSelect(t, c.spec, c.active)
		if got := sources(f); got != c.sources {
			t.Errorf("%s: sources %q, want %q", c.name, got, c.sources)
		}
		for _, s := range Sources() {
			want := strings.Contains(","+c.sources+",", ","+string(s)+",")
			if f.Needs(s) != want {
				t.Errorf("%s: Needs(%s) = %v, want %v", c.name, s, f.Needs(s), want)
			}
		}
		if f.NeedsProbe() != c.probe || f.NeedsTLS() != c.tls || f.NeedsWeb() != c.web || f.NeedsSharedCheck() != c.shared {
			t.Errorf("%s: probe %v tls %v web %v shared %v, want %v %v %v %v", c.name,
				f.NeedsProbe(), f.NeedsTLS(), f.NeedsWeb(), f.NeedsSharedCheck(), c.probe, c.tls, c.web, c.shared)
		}
	}
	var zero Fields
	if zero.Needs(SourceCymru) || zero.NeedsProbe() || zero.NeedsSharedCheck() {
		t.Error("the zero selection needs a source")
	}
}

func TestFields_NeedsDefaultAllNeverProbes(t *testing.T) {
	t.Parallel()
	f := AllFields(false)
	if f.Needs(SourceProbe) || f.NeedsProbe() || f.NeedsSharedCheck() {
		t.Error("the default mode probes or checks sharing")
	}
}

// encode is v as the command writes it: without HTML escaping.
func encode(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func full() Record {
	r := Record{
		Address: "203.0.113.9", Hostnames: []string{"a.example.com", "b.example.com"}, Kind: "documentation",
		ASN: new(uint32(64500)), ASName: new("EXAMPLE-AS, ZZ"), ASPrefix: new("203.0.113.0/24"),
		RDAPNetblock: new("203.0.113.0/24"), RDAPOrg: new("Example <Org> & Co"), RDAPRegistry: new("ARIN"),
		PTR: []string{"host.example.com"}, Provider: new("Example Cloud"), ProviderClass: new("hyperscaler"),
		GeoCountry: new("AU"), GeoCity: nil,
		InternetDBPorts: []int{22, 443}, InternetDBHostnames: []string{}, InternetDBTags: []string{"cloud"},
		InternetDBCPEs: []string{}, InternetDBVulns: []string{"CVE-2024-3094"},
		ReverseIP: []string{"x.example.com"}, ReverseIPCount: new(1),
		NotContacted: nil,
		Ports:        []Port{{Port: 22, State: PortOpen, Banner: new("SSH-2.0-x")}, {Port: 25, State: PortClosed}},
		TLS: []TLSEntry{{Port: 443, ServerName: new("a.example.com"), Outcome: OutcomeOK, Names: []string{"a.example.com"},
			Issuer: new("Test CA"), Expiry: new("2027-01-01")}, {Port: 465, Outcome: OutcomeNotTLS}},
		Web: []WebEntry{{Port: 443, Scheme: "https", Host: "a.example.com", Outcome: OutcomeOK, Status: new(301), Server: new("nginx"),
			Title: new("Hi"), Location: new("https://a.example.com/x")}},
	}
	r.AddFailure(Failure{Source: SourceRIPEstat, Code: clierr.Timeout, Message: "late", Transient: true})
	return r
}

func TestProjected_EveryKeyInOrder(t *testing.T) {
	t.Parallel()
	want := `{"address":"203.0.113.9","hostnames":["a.example.com","b.example.com"],"kind":"documentation",` +
		`"asn":64500,"as_name":"EXAMPLE-AS, ZZ","as_prefix":"203.0.113.0/24",` +
		`"rdap_netblock":"203.0.113.0/24","rdap_org":"Example <Org> & Co","rdap_registry":"ARIN",` +
		`"ptr":["host.example.com"],"provider":"Example Cloud","provider_class":"hyperscaler",` +
		`"geo_country":"AU","geo_city":null,` +
		`"internetdb_ports":[22,443],"internetdb_hostnames":[],"internetdb_tags":["cloud"],"internetdb_cpes":[],"internetdb_vulns":["CVE-2024-3094"],` +
		`"reverse_ip":["x.example.com"],"reverse_ip_count":1,` +
		`"not_contacted":null,` +
		`"ports":[{"port":22,"state":"open","banner":"SSH-2.0-x"},{"port":25,"state":"closed","banner":null}],` +
		`"tls":[{"port":443,"server_name":"a.example.com","outcome":"ok","names":["a.example.com"],"issuer":"Test CA","expiry":"2027-01-01"},` +
		`{"port":465,"server_name":null,"outcome":"not-tls","names":[],"issuer":null,"expiry":null}],` +
		`"web":[{"port":443,"scheme":"https","host":"a.example.com","outcome":"ok","status":301,"server":"nginx","title":"Hi","location":"https://a.example.com/x"}],` +
		`"failures":[{"source":"ripestat","code":"TIMEOUT","message":"late","transient":true,"quota":false}]}`
	if got := encode(t, AllFields(true).Project(full())); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestProjected_OnlyTheSelectedKeys(t *testing.T) {
	t.Parallel()
	r := full()
	if got, want := encode(t, mustSelect(t, "asn", false).Project(r)),
		`{"address":"203.0.113.9","hostnames":["a.example.com","b.example.com"],"kind":"documentation","asn":64500,`+
			`"failures":[{"source":"ripestat","code":"TIMEOUT","message":"late","transient":true,"quota":false}]}`; got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	// The default mode never writes an active key, even for a record that holds them.
	got := encode(t, AllFields(false).Project(r))
	for _, k := range []string{`"not_contacted"`, `"ports"`, `"tls"`, `"web"`} {
		if strings.Contains(got, k) {
			t.Errorf("default mode wrote %s: %s", k, got)
		}
	}
	// Nothing selected: the four always-present keys, and a record with nothing to say still has [].
	bare := Record{Address: "10.0.0.1", Kind: "private"}
	if got, want := encode(t, mustSelect(t, "", false).Project(bare)),
		`{"address":"10.0.0.1","hostnames":[],"kind":"private","failures":[]}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestProjected_UnknownIsNullAndNoneIsEmpty(t *testing.T) {
	t.Parallel()
	failed := Record{Address: "1.1.1.1", Kind: "public"}
	got := encode(t, AllFields(true).Project(failed))
	want := `{"address":"1.1.1.1","hostnames":[],"kind":"public","asn":null,"as_name":null,"as_prefix":null,` +
		`"rdap_netblock":null,"rdap_org":null,"rdap_registry":null,"ptr":null,"provider":null,"provider_class":null,` +
		`"geo_country":null,"geo_city":null,"internetdb_ports":null,"internetdb_hostnames":null,"internetdb_tags":null,` +
		`"internetdb_cpes":null,"internetdb_vulns":null,"reverse_ip":null,"reverse_ip_count":null,` +
		`"not_contacted":null,"ports":null,"tls":null,"web":null,"failures":[]}`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	answered := Record{Address: "1.1.1.1", Kind: "public", PTR: []string{}, InternetDBPorts: []int{}, ReverseIP: []string{}}
	got = encode(t, mustSelect(t, "ptr,internetdb_ports,reverse_ip", false).Project(answered))
	want = `{"address":"1.1.1.1","hostnames":[],"kind":"public","ptr":[],"internetdb_ports":[],"reverse_ip":[],"failures":[]}`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestProjected_Accessors(t *testing.T) {
	t.Parallel()
	f := mustSelect(t, "asn", false)
	p := f.Project(full())
	if p.Record().Address != "203.0.113.9" || !p.Fields().Has("asn") || p.Fields().Has("ptr") {
		t.Errorf("accessors: %v", p.Fields().Names())
	}
}
