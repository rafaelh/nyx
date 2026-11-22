package cli_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/dnsname"
)

// nyx ip: inputs, hostnames, CIDRs, the cap, non-public addresses, the record of a public address,
// --fields and the envelope. Every host nyx ip asks, and every address it may connect to, is a fake
// from ip_world_test.go; a test that leaks a request shows up as a count.

// ---- inputs ----

// A bare nyx ip, a - beside other arguments, and a - with nothing on stdin are usage errors, and
// nothing is asked.
func TestIP_NoInputsIsAUsageError(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		args  []string
		stdin string
	}{
		{"no arguments", nil, ""},
		{"empty stdin", []string{"-"}, ""},
		{"blank stdin", []string{"-"}, "\n  \n\t\n"},
	} {
		for _, jsonMode := range modes {
			w := newIPWorld(t)
			w.h.stdin = strings.NewReader(c.stdin)
			args := slices.Clone(c.args)
			if jsonMode {
				args = append(args, "--json")
			}
			f := w.h.failed(w.run(args...), 2, jsonMode)
			if f.code != "INVALID_INPUT" {
				t.Errorf("%s (json=%v): %+v", c.name, jsonMode, f)
			}
			w.untouched()
		}
	}
}

// A - beside other arguments is a usage error, found before stdin is read.
func TestIP_DashWithOtherArgumentsIsAUsageError(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"-", "8.8.4.4"}, {"8.8.4.4", "-"}, {"-", "-"}} {
		for _, jsonMode := range modes {
			w := newIPWorld(t)
			w.h.stdin = readSpy{t}
			args := slices.Clone(args)
			if jsonMode {
				args = append(args, "--json")
			}
			f := w.h.failed(w.run(args...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "-") {
				t.Errorf("%v: %+v", args, f)
			}
			w.untouched()
		}
	}
}

// A stdin that is never closed ends at the deadline as a timeout, and the call returns.
func TestIP_StdinNeverClosedTimesOut(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		r, pw := io.Pipe()
		t.Cleanup(func() { pw.Close() })
		w.h.stdin = r
		args := []string{"-", "--timeout", "300ms"}
		if jsonMode {
			args = append(args, "--json")
		}
		start := time.Now()
		f := w.h.failed(w.run(args...), 1, jsonMode)
		if f.code != "TIMEOUT" || !strings.Contains(f.msg, "stdin") {
			t.Errorf("json=%v: %+v", jsonMode, f)
		}
		if el := time.Since(start); el > 3*time.Second {
			t.Errorf("the call took %v", el)
		}
		w.untouched()
	}
}

// Blank lines are ignored and white space around an input is trimmed, with either line ending.
func TestIP_StdinLinesAreTrimmed(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.stdin = strings.NewReader("\n  8.8.4.4  \n\n\t1.1.1.1\r\n   \n9.9.9.9")
	env := w.lookup("-", "--fields", "")
	if got := env.addresses(); !slices.Equal(got, []string{"8.8.4.4", "1.1.1.1", "9.9.9.9"}) {
		t.Errorf("addresses %v", got)
	}
	w.untouched()
}

// There is no --config: no settings apply to nyx ip.
func TestIP_ConfigIsAnUnknownFlag(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		args := []string{"8.8.4.4", "--config", filepath.Join(t.TempDir(), "nyx.yaml")}
		if jsonMode {
			args = append(args, "--json")
		}
		f := w.h.failed(w.run(args...), 2, jsonMode)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "unknown flag: --config") {
			t.Errorf("json=%v: %+v", jsonMode, f)
		}
		if jsonMode && !slices.Equal(f.inputOf("flag"), []string{"--config"}) {
			t.Errorf("input %v", f.input)
		}
		w.untouched()
	}
}

// Neither a configuration file nor a NYX_* variable changes anything: not the result, not where
// anything is written, and an invalid one is not an error.
func TestIP_SettingsAreNotRead(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.seed("8.8.4.4")
	if code := w.runJSON("8.8.4.4"); code != 0 {
		t.Fatalf("exit %d: %s", code, w.h.stderr.String())
	}
	want := w.h.stdout.String()

	cfgDir := filepath.Join(w.h.env["XDG_CONFIG_HOME"], "nyx")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfgDir, "config.yaml", "rate: [this is not a valid setting\n")
	w.h.setenv("NYX_OUTPUT_DIR", w.h.out)
	w.h.setenv("NYX_RATE_PER_SOURCE", "not-a-number")
	w.h.setenv("NYX_NO_SUCH_SETTING", "1")
	w.h.setenv("NYX_TIMEOUT", "1ns")
	w.h.setenv("NYX_KEYS_SHODAN", "secret-key-value")
	if code := w.runJSON("8.8.4.4"); code != 0 {
		t.Fatalf("with settings: exit %d: %s", code, w.h.stderr.String())
	}
	if got := w.h.stdout.String(); got != want {
		t.Errorf("settings changed the result:\n got %s\nwant %s", got, want)
	}
	if strings.Contains(w.h.stdout.String()+w.h.stderr.String(), "secret-key-value") {
		t.Error("a key reached the output")
	}
}

// nyx ip writes no file: not in the working directory, not in the output directory a setting names,
// not in the configuration directory.
func TestIP_WritesNoFiles(t *testing.T) {
	t.Parallel()
	listing := func(dir string) string {
		var out []string
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && p != dir {
				out = append(out, p)
			}
			return nil
		})
		return strings.Join(out, "\n")
	}
	w := newIPWorld(t)
	w.seed("8.8.4.4")
	w.h.set("output_dir", w.h.out)
	cfg := w.h.env["XDG_CONFIG_HOME"]
	before, cfgBefore := listing("."), listing(cfg) // the harness leaves an empty config file there
	for _, args := range [][]string{{"8.8.4.4"}, {"8.8.4.4", "https://example.com/x"}, {"8.8.4.4", "--fields", "ptr"}} {
		for _, jsonMode := range modes {
			args := slices.Clone(args)
			if jsonMode {
				args = append(args, "--json")
			}
			w.run(args...)
		}
	}
	if got := listing(w.h.out); got != "" {
		t.Errorf("the output directory holds %q", got)
	}
	if got := listing(cfg); got != cfgBefore {
		t.Errorf("the configuration directory changed:\nbefore %q\nafter  %q", cfgBefore, got)
	}
	if got := listing("."); got != before {
		t.Errorf("the working directory changed:\nbefore %q\nafter  %q", before, got)
	}
}

// ---- hostnames and invalid inputs ----

// A URL or a host and port is an invalid input whose hint names the bare host.
func TestIP_URLAndHostPortHintAtTheBareHost(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ input, host string }{
		{"https://example.com/path?q=1", "example.com"},
		{"http://8.8.4.4:8080/x", "8.8.4.4"},
		{"example.com:8080", "example.com"},
		{"8.8.4.4:443", "8.8.4.4"},
		{"[2001:db8::1]:443", "2001:db8::1"},
	} {
		t.Run(c.input, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			f := w.h.failed(w.runJSON(c.input), 2, true)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.hint, c.host) || !slices.Equal(f.inputOf("input"), []string{c.input}) {
				t.Errorf("%+v", f)
			}
			w.untouched()
		})
	}
}

// Every invalid input is reported together when the call exits 2: a name of digits and dots, a
// single-label name without --active, a malformed name and a URL.
func TestIP_EveryInvalidInputIsListedTogether(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	bad := []string{"https://example.com/x", "123", "1.2.3", "intranet", "bad_name!", "a..example.com"}
	f := w.h.failed(w.runJSON(bad...), 2, true)
	if f.code != "INVALID_INPUT" {
		t.Fatalf("%+v", f)
	}
	if got := f.inputOf("input"); !slices.Equal(got, bad) {
		t.Errorf("input %v, want every invalid input %v", got, bad)
	}
	for _, in := range bad {
		if !strings.Contains(f.msg, in) {
			t.Errorf("the message leaves out %q: %s", in, f.msg)
		}
	}
	w.untouched()
}

// A single-label name is a hostname only under --active, and then this machine's resolver is the
// only one asked: the public resolvers never see it.
func TestIP_SingleLabelNamesResolveOnlyThroughTheLocalResolver(t *testing.T) { // mutation target
	t.Parallel()
	t.Run("without --active", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.local.A("intranet", "8.8.4.4")
		w.dns.A("intranet", "9.9.9.9")
		f := w.h.failed(w.runJSON("intranet"), 2, true)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.hint, "--active") || !slices.Equal(f.inputOf("input"), []string{"intranet"}) {
			t.Errorf("%+v", f)
		}
		w.untouched()
	})
	t.Run("with --active", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.local.A("intranet", "8.8.4.4")
		w.dns.A("intranet", "9.9.9.9") // what a public resolver would say if it were asked
		w.sealProbes([]string{"8.8.4.4", "9.9.9.9"})
		env := w.lookup("intranet", "--active", "--fields", "")
		if len(env.Records) != 1 || env.Records[0].address() != "8.8.4.4" || !slices.Equal(env.Records[0].strs("hostnames"), []string{"intranet"}) {
			t.Fatalf("data %s", w.h.stdout.String())
		}
		for _, n := range dnsNames(w.dns) {
			if strings.Contains(n, "intranet") {
				t.Errorf("the public resolvers were asked for %s", n)
			}
		}
		if w.local.Count("intranet", "A") == 0 {
			t.Error("this machine's resolver was not asked for intranet")
		}
		if w.httpRequests() != 0 || len(w.contacted()) != 0 {
			t.Errorf("requests %d, connections %v", w.httpRequests(), w.contacted())
		}
	})
}

// One invalid input among valid ones does not stop the others: they are returned, the call exits 7
// and the failure is in meta.errors under the input as given.
func TestIP_OneInvalidInputAmongValidExits7(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	env, f := w.partial("8.8.4.4", "https://example.com/x", "1.1.1.1", "--fields", "")
	if got := env.addresses(); !slices.Equal(got, []string{"8.8.4.4", "1.1.1.1"}) {
		t.Errorf("addresses %v", got)
	}
	if len(env.Meta.Errors) != 1 {
		t.Fatalf("meta.errors %+v", env.Meta.Errors)
	}
	e := env.Meta.Errors[0]
	if e.Code != "INVALID_INPUT" || e.Transient || !slices.Equal(e.inputs(), []string{"https://example.com/x"}) || e.address() != "" ||
		e.Hint == nil || !strings.Contains(*e.Hint, "example.com") {
		t.Errorf("entry %+v", e)
	}
	if f.transient {
		t.Errorf("an invalid input is not worth retrying: %+v", f)
	}
}

// ---- resolving hostnames ----

// A name with no address (NXDOMAIN) and a name with no A and no AAAA record (NODATA) are NOT_FOUND:
// exit 3, nothing on stdout, and the hostname is in the error.
func TestIP_NamesWithNoAddressAreNotFound(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, host string }{{"NXDOMAIN", "nx.example.com"}, {"NODATA", "nodata.example.com"}} {
		for _, jsonMode := range modes {
			w := newIPWorld(t)
			w.dns.TXT("nodata.example.com", "v=other") // known to the resolver, with no address
			args := []string{c.host}
			if jsonMode {
				args = append(args, "--json")
			}
			f := w.h.failed(w.run(args...), 3, jsonMode)
			if f.code != "NOT_FOUND" || !strings.Contains(f.msg, c.host) || f.transient {
				t.Errorf("%s (json=%v): %+v", c.name, jsonMode, f)
			}
			if w.httpRequests() != 0 {
				t.Errorf("%s: %d HTTP requests", c.name, w.httpRequests())
			}
		}
	}
}

// A resolver that fails is transient: SERVFAIL is NETWORK_ERROR, and a resolver that never answers
// is TIMEOUT once the deadline has passed.
func TestIP_ResolverFailuresAreTransient(t *testing.T) {
	t.Parallel()
	t.Run("SERVFAIL", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.dns.Rcode("broken.example.com", int(mdns.RcodeServerFailure))
		f := w.h.failed(w.runJSON("broken.example.com"), 1, true)
		if f.code != "NETWORK_ERROR" || !f.transient {
			t.Errorf("%+v", f)
		}
	})
	t.Run("no answer by the deadline", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.dns.Drop("slow.example.com")
		f := w.h.failed(w.runJSON("slow.example.com", "--timeout", "100ms"), 1, true)
		if f.code != "TIMEOUT" || !f.transient {
			t.Errorf("%+v", f)
		}
	})
	t.Run("no answer by the resolver's own timeout", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.dns.Drop("slow.example.com")
		f := w.h.failed(w.runJSON("slow.example.com"), 1, true)
		if (f.code != "TIMEOUT" && f.code != "NETWORK_ERROR") || !f.transient {
			t.Errorf("%+v", f)
		}
	})
}

// Under --active a name the public resolvers do not know (NXDOMAIN or no addresses) is tried again
// through this machine's resolver; without --active it is not, and a name they do know is never sent
// to it.
func TestIP_ActiveRetriesAnUnknownNameThroughTheLocalResolver(t *testing.T) {
	t.Parallel()
	t.Run("NXDOMAIN", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.local.A("corp.example.com", "8.8.4.4")
		w.sealProbes([]string{"8.8.4.4"})
		rec := w.record("corp.example.com", "--active", "--fields", "")
		if rec.address() != "8.8.4.4" || !slices.Equal(rec.strs("hostnames"), []string{"corp.example.com"}) {
			t.Errorf("record %s", rec.raw)
		}
		if w.dns.Count("corp.example.com", "A") == 0 || w.local.Count("corp.example.com", "A") == 0 {
			t.Errorf("public A %d, local A %d", w.dns.Count("corp.example.com", "A"), w.local.Count("corp.example.com", "A"))
		}
	})
	t.Run("no addresses", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.dns.TXT("corp.example.com", "v=other")
		w.local.A("corp.example.com", "8.8.4.4")
		w.sealProbes([]string{"8.8.4.4"})
		if rec := w.record("corp.example.com", "--active", "--fields", ""); rec.address() != "8.8.4.4" {
			t.Errorf("record %s", rec.raw)
		}
	})
	t.Run("not under the default mode", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.local.A("corp.example.com", "8.8.4.4")
		f := w.h.failed(w.runJSON("corp.example.com"), 3, true)
		if f.code != "NOT_FOUND" {
			t.Errorf("%+v", f)
		}
		if w.local.Total() != 0 {
			t.Errorf("this machine's resolver was asked: %v", dnsNames(w.local))
		}
	})
	t.Run("a name the public resolvers know", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.dns.A("known.example.com", "8.8.4.4")
		w.local.A("known.example.com", "9.9.9.9")
		w.sealProbes([]string{"8.8.4.4", "9.9.9.9"})
		rec := w.record("known.example.com", "--active", "--fields", "")
		if rec.address() != "8.8.4.4" || w.local.Total() != 0 {
			t.Errorf("record %s, local queries %v", rec.raw, dnsNames(w.local))
		}
	})
}

// ---- CIDRs, order and duplicates ----

// A CIDR's host bits are masked and it expands to every address in it, the first and last included,
// in address order and canonical form; nothing is asked for them with no field selected.
func TestIP_CIDRsExpandInOrder(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		input string
		want  []string
	}{
		{"8.8.4.5/30", []string{"8.8.4.4", "8.8.4.5", "8.8.4.6", "8.8.4.7"}},
		{"8.8.4.4/32", []string{"8.8.4.4"}},
		{"2606:4700::5/126", []string{"2606:4700::4", "2606:4700::5", "2606:4700::6", "2606:4700::7"}},
	} {
		w := newIPWorld(t)
		env := w.lookup(c.input, "--fields", "")
		if got := env.addresses(); !slices.Equal(got, c.want) {
			t.Errorf("%s: addresses %v, want %v", c.input, got, c.want)
		}
		for _, r := range env.Records {
			if len(r.strs("hostnames")) != 0 || r.list("hostnames") == nil || r.str("kind") != "public" {
				t.Errorf("%s: record %s", c.input, r.raw)
			}
		}
		w.untouched()
	}
}

// A hostname gives its IPv4 addresses first and then its IPv6 ones, each in address order, whatever
// order the resolver sent them in.
func TestIP_HostnameAddressesComeIPv4ThenIPv6InOrder(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.dns.A("multi.example.com", "9.9.9.9", "8.8.4.4", "2606:4700::2", "2606:4700::1")
	env := w.lookup("multi.example.com", "--fields", "")
	if got, want := env.addresses(), []string{"8.8.4.4", "9.9.9.9", "2606:4700::1", "2606:4700::2"}; !slices.Equal(got, want) {
		t.Errorf("addresses %v, want %v", got, want)
	}
	for _, r := range env.Records {
		if !slices.Equal(r.strs("hostnames"), []string{"multi.example.com"}) {
			t.Errorf("record %s", r.raw)
		}
	}
}

// An address that several inputs give has one record, where it first appeared, listing every input
// hostname that gave it; a literal and a CIDR give none to list.
func TestIP_DuplicatesGiveOneRecordAtFirstAppearance(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.dns.A("a.example.com", "8.8.4.4")
	w.dns.A("b.example.com", "9.9.9.9", "8.8.4.4")
	env := w.lookup("a.example.com", "8.8.4.4/31", "8.8.4.5", "b.example.com", "--fields", "")
	if got, want := env.addresses(), []string{"8.8.4.4", "8.8.4.5", "9.9.9.9"}; !slices.Equal(got, want) {
		t.Fatalf("addresses %v, want %v", got, want)
	}
	for i, want := range [][]string{{"a.example.com", "b.example.com"}, {}, {"b.example.com"}} {
		if got := env.Records[i].strs("hostnames"); !slices.Equal(got, want) || env.Records[i].list("hostnames") == nil {
			t.Errorf("%s: hostnames %v, want %v", env.Records[i].address(), got, want)
		}
	}
}

// An IPv4-mapped IPv6 address is the IPv4 address, and one record serves both spellings.
func TestIP_IPv4MappedAddressIsTheIPv4Address(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	env := w.lookup("::ffff:1.2.3.4", "1.2.3.4", "::FFFF:0102:0304", "--fields", "")
	if got := env.addresses(); !slices.Equal(got, []string{"1.2.3.4"}) {
		t.Errorf("addresses %v", got)
	}
	if env.Records[0].str("kind") != "public" {
		t.Errorf("record %s", env.Records[0].raw)
	}
	w.untouched()
}

// ---- the cap ----

// A call holds at most 256 distinct addresses: exactly 256 is allowed, and more than that from
// literals and CIDRs alone exits 2 before anything is sent.
func TestIP_MoreThan256AddressesIsRefusedBeforeAnyRequest(t *testing.T) {
	t.Parallel()
	var literals []string
	for i := range 300 {
		literals = append(literals, fmt.Sprintf("8.9.%d.%d", i/200, i%200+1))
	}
	for _, c := range []struct {
		name string
		args []string
	}{
		{"a /23", []string{"8.8.4.0/23"}},
		{"a /24 and one more", []string{"8.8.4.0/24", "9.9.9.9"}},
		{"two /24s", []string{"8.8.4.0/24", "8.8.5.0/24"}},
		{"an IPv6 /64", []string{"2606:4700::/64"}},
		{"300 literals", literals},
		{"a /8", []string{"8.0.0.0/8"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			f := w.h.failed(w.runJSON(c.args...), 2, true)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "256") {
				t.Errorf("%+v", f)
			}
			w.untouched()
		})
	}
	t.Run("exactly 256", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		env := w.lookup("8.8.4.0/24", "--fields", "")
		if len(env.Records) != 256 || env.Meta.Count != 256 {
			t.Errorf("%d records", len(env.Records))
		}
		w.untouched()
	})
	t.Run("distinct addresses are counted", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		env := w.lookup("8.8.4.0/24", "8.8.4.7", "8.8.4.0/25", "--fields", "")
		if len(env.Records) != 256 {
			t.Errorf("%d records", len(env.Records))
		}
		w.untouched()
	})
}

// Addresses from hostnames count once the hostnames resolve: past 256, the call exits 2 having sent
// only the DNS lookups of the names.
func TestIP_HostnamesPastTheCapSendOnlyDNSLookups(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	var names []string
	for i := range 30 {
		name := fmt.Sprintf("h%02d.example.com", i)
		names = append(names, name)
		for j := range 10 {
			w.dns.A(name, fmt.Sprintf("8.%d.%d.1", 10+i, j))
		}
	}
	f := w.h.failed(w.runJSON(names...), 2, true)
	if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "256") {
		t.Errorf("%+v", f)
	}
	if n := w.httpRequests(); n != 0 || w.local.Total() != 0 || len(w.contacted()) != 0 {
		t.Errorf("HTTP requests %d, local queries %v, connections %v", n, dnsNames(w.local), w.contacted())
	}
	for _, ty := range []string{"TXT", "PTR", "MX", "NS", "SOA", "CAA", "SRV"} {
		if q := w.dns.Queried(ty); len(q) != 0 {
			t.Errorf("the public resolvers were asked %s for %v", ty, q)
		}
	}
	if w.dns.Total() == 0 {
		t.Error("the names were not looked up")
	}
}

// A call that exits 2 at the cap still reports every invalid input with it, whether the literals
// pass the cap or the hostnames do once they resolve.
func TestIP_TheCapErrorListsTheInvalidInputsToo(t *testing.T) {
	t.Parallel()
	t.Run("literals", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		f := w.h.failed(w.runJSON("bad_name!", "8.8.4.0/23"), 2, true)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "256") || !strings.Contains(f.msg, "bad_name!") {
			t.Errorf("%+v", f)
		}
		if got := f.inputOf("input"); !slices.Contains(got, "bad_name!") {
			t.Errorf("input %v leaves out the invalid input", got)
		}
		w.untouched()
	})
	t.Run("hostnames", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		args := []string{"bad_name!"}
		for i := range 30 {
			name := fmt.Sprintf("h%02d.example.com", i)
			args = append(args, name)
			for j := range 10 {
				w.dns.A(name, fmt.Sprintf("8.%d.%d.1", 10+i, j))
			}
		}
		f := w.h.failed(w.runJSON(args...), 2, true)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "256") || !strings.Contains(f.msg, "bad_name!") {
			t.Errorf("%+v", f)
		}
		if got := f.inputOf("input"); !slices.Contains(got, "bad_name!") {
			t.Errorf("input %v leaves out the invalid input", got)
		}
	})
}

// reverseName is the PTR name of an address, as the DNS fakes hold it.
func reverseName(addr string) string {
	rev, err := mdns.ReverseAddr(addr)
	if err != nil {
		panic(err)
	}
	return dnsname.Normalise(rev)
}

// ---- non-public addresses ----

// nonPublic are addresses IANA's special-purpose registries mark as not globally reachable, with the
// kind each one is called.
var nonPublic = []struct{ addr, kind string }{
	{"10.0.0.1", "private"}, {"100.64.0.1", "cgnat"}, {"fd00::1", "ula"}, {"169.254.1.1", "link-local"},
	{"192.0.2.1", "documentation"}, {"224.0.0.1", "multicast"}, {"255.255.255.255", "broadcast"},
	{"0.0.0.0", "unspecified"}, {"2002::1", "6to4"}, {"2001::1", "teredo"}, {"127.0.0.1", "loopback"}, {"::1", "loopback"},
}

// A non-public address names its kind and is sent to no third party and to no public resolver:
// nothing is asked about it, its reverse name included. Every selected key is empty and it is a
// success. Every source has an answer for it, so a request would show in the record as well.
func TestIP_NonPublicAddressesAreNeverSentToAThirdParty(t *testing.T) { // mutation target
	t.Parallel()
	w := newIPWorld(t)
	var addrs []string
	for _, c := range nonPublic {
		addrs = append(addrs, c.addr)
		w.seed(c.addr)
	}
	w.sealProbes(addrs)
	env := w.lookup(addrs...)
	if len(env.Records) != len(nonPublic) {
		t.Fatalf("%d records, want %d: %s", len(env.Records), len(nonPublic), w.h.stdout.String())
	}
	for i, c := range nonPublic {
		r := env.Records[i]
		if r.address() != c.addr || r.str("kind") != c.kind {
			t.Errorf("%s: address %q kind %q, want %q", c.addr, r.address(), r.str("kind"), c.kind)
		}
		if !slices.Equal(r.keys, ipDefaultKeys) {
			t.Errorf("%s: keys %v", c.addr, r.keys)
		}
		for _, k := range ipSourceKeys(false) {
			if !r.emptyValue(k) {
				t.Errorf("%s: %s = %v, want null or []", c.addr, k, r.m[k])
			}
		}
		if len(r.failures()) != 0 || len(r.strs("hostnames")) != 0 {
			t.Errorf("%s: %s", c.addr, r.raw)
		}
	}
	w.untouched()
	w.neverSent(addrs...)
}

// A hostname that public DNS says is a non-public address gives a record of that kind, with its
// hostname, and nothing but the lookup of the name is sent.
func TestIP_NonPublicAddressFromAHostnameIsNotSentAnywhere(t *testing.T) { // mutation target
	t.Parallel()
	w := newIPWorld(t)
	w.dns.A("internal.example.com", "10.0.0.5")
	w.seed("10.0.0.5")
	w.sealProbes([]string{"10.0.0.5"})
	rec := w.record("internal.example.com")
	if rec.address() != "10.0.0.5" || rec.str("kind") != "private" || !slices.Equal(rec.strs("hostnames"), []string{"internal.example.com"}) {
		t.Errorf("record %s", rec.raw)
	}
	for _, k := range ipSourceKeys(false) {
		if !rec.emptyValue(k) {
			t.Errorf("%s = %v", k, rec.m[k])
		}
	}
	if w.httpRequests() != 0 || len(w.contacted()) != 0 || w.local.Total() != 0 {
		t.Errorf("HTTP %d, connections %v, local %v", w.httpRequests(), w.contacted(), dnsNames(w.local))
	}
	for _, ty := range []string{"TXT", "PTR"} {
		if q := w.dns.Queried(ty); len(q) != 0 {
			t.Errorf("the public resolvers were asked %s for %v", ty, q)
		}
	}
}

// Under --active the PTR of a non-public address is looked up through this machine's resolver and
// only there.
func TestIP_ActiveLooksUpANonPublicPTROnlyLocally(t *testing.T) { // mutation target
	t.Parallel()
	w := newIPWorld(t)
	addrs := []string{"10.0.0.1", "fd00::1", "192.0.2.1"}
	for _, a := range addrs {
		w.seed(a) // the public resolvers hold a PTR for each too
		w.local.PTR(a, "gw."+strings.NewReplacer(".", "-", ":", "-").Replace(a)+".corp.example")
	}
	w.sealProbes(addrs)
	env := w.lookup(append(slices.Clone(addrs), "--active", "--fields", "ptr")...)
	for i, a := range addrs {
		r := env.Records[i]
		want := []string{"gw." + strings.NewReplacer(".", "-", ":", "-").Replace(a) + ".corp.example"}
		if !slices.Equal(r.strs("ptr"), want) || len(r.failures()) != 0 {
			t.Errorf("%s: record %s, want ptr %v", a, r.raw, want)
		}
		if n := w.local.Count(reverseName(a), "PTR"); n != 1 {
			t.Errorf("%s: this machine's resolver was asked for its PTR %d times", a, n)
		}
	}
	if w.dns.Total() != 0 || w.httpRequests() != 0 {
		t.Errorf("public queries %v, HTTP %d", dnsNames(w.dns), w.httpRequests())
	}
	sawOnly(t, w.local, "PTR", reverseName("10.0.0.1"), reverseName("fd00::1"), reverseName("192.0.2.1"))
}

// A failure of the local PTR lookup of a non-public address is a failure of its ptr source; the other
// address, whose lookup worked, is returned.
func TestIP_ActiveLocalPTRFailureIsReported(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.local.PTR("10.0.0.2", "ok.corp.example")
	w.local.Rcode(reverseName("10.0.0.1"), int(mdns.RcodeServerFailure))
	w.sealProbes([]string{"10.0.0.1", "10.0.0.2"})
	// A non-public address is a success whatever its local lookup does: the failure is listed in
	// its record, and the call still exits 0.
	env := w.lookup("10.0.0.1", "10.0.0.2", "--active", "--fields", "ptr")
	if len(env.Records) != 2 || len(env.Meta.Errors) != 0 {
		t.Fatalf("envelope %s", w.h.stdout.String())
	}
	for _, r := range env.Records {
		switch r.address() {
		case "10.0.0.2":
			if !slices.Equal(r.strs("ptr"), []string{"ok.corp.example"}) {
				t.Errorf("10.0.0.2: %s", r.raw)
			}
		case "10.0.0.1":
			if f := r.failureOf("ptr"); f.Code != "NETWORK_ERROR" || !f.Transient || !r.isNull("ptr") {
				t.Errorf("10.0.0.1: %s", r.raw)
			}
		}
	}
}

// cymruOriginName is the name Team Cymru's origin lookup of an address asks for.
func cymruOriginName(addr string) string { return dnsname.CymruOrigin(netip.MustParseAddr(addr)) }

// ---- the record of a public address ----

// A public address's record has every key in the documented order, with the value each source gave.
func TestIP_AFullRecordHasEveryKeyInOrder(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	facts := w.seed("8.8.4.4")
	w.sealProbes([]string{"8.8.4.4"})
	rec := w.record("8.8.4.4")
	if !slices.Equal(rec.keys, ipDefaultKeys) {
		t.Errorf("keys %v, want %v", rec.keys, ipDefaultKeys)
	}
	facts.check(t, rec)
	if len(rec.failures()) != 0 || rec.str("kind") != "public" || len(rec.strs("hostnames")) != 0 || rec.list("hostnames") == nil {
		t.Errorf("record %s", rec.raw)
	}
	if !strings.Contains(string(rec.raw), `"asn":64500,`) || !strings.Contains(string(rec.raw), `"internetdb_ports":[22,80,443]`) {
		t.Errorf("asn and ports are numbers: %s", rec.raw)
	}
	if w.h.stderr.Len() != 0 {
		t.Errorf("stderr %q", w.h.stderr.String())
	}
	if len(w.contacted()) != 0 {
		t.Errorf("connections to %v", w.contacted())
	}
}

// An IPv6 address has the same keys; HackerTarget is not asked for it and the reverse-IP keys are
// null, which is not a failure.
func TestIP_AnIPv6AddressIsNotAskedOfHackerTarget(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	facts := w.seed("2001:4860:4860::8888", ipProviderOf("", "", true))
	rec := w.record("2001:4860:4860::8888")
	if !slices.Equal(rec.keys, ipDefaultKeys) || !rec.isNull("reverse_ip") || !rec.isNull("reverse_ip_count") || len(rec.failures()) != 0 {
		t.Errorf("record %s", rec.raw)
	}
	facts.check(t, rec)
	if w.ht.count() != 0 {
		t.Errorf("HackerTarget was asked: %v", w.ht.requests())
	}
}

// A source that has nothing to say about the address has answered: its keys are empty, not a failure.
func TestIP_ASourceWithNothingToSayHasAnswered(t *testing.T) {
	t.Parallel()
	none := func(keys ...string) func(*ipFacts) {
		return func(f *ipFacts) {
			for _, k := range keys {
				switch k {
				case "cymru":
					f.ASN, f.ASName, f.ASPrefix = 0, "", ""
				case "rdap":
					f.Netblock, f.Org, f.Registry = "", "", ""
				case "ptr":
					f.PTR = nil
				case "ripestat":
					f.Country, f.City = "", ""
				case "internetdb":
					f.Ports, f.Hostnames, f.Tags, f.CPEs, f.Vulns = nil, nil, nil, nil, nil
				case "hackertarget":
					f.Reverse, f.ReverseCount = nil, 0
				}
			}
		}
	}
	for _, c := range []struct {
		name  string
		mod   func(*ipFacts)
		after func(w *ipWorld)
	}{
		{"every source", none("cymru", "rdap", "ptr", "ripestat", "internetdb", "hackertarget"), nil},
		{"Team Cymru", none("cymru"), nil},
		{"RDAP", none("rdap"), nil},
		{"the PTR lookup", none("ptr"), nil},
		{"RIPEstat", none("ripestat"), nil},
		{"InternetDB with a 404", none("internetdb"), nil},
		{"InternetDB with empty lists", none("internetdb"), func(w *ipWorld) { w.internetDB("8.8.4.4", nil, nil, nil, nil, nil) }},
		{"HackerTarget with no records", none("hackertarget"), nil},
		{"HackerTarget with an empty body", none("hackertarget"), func(w *ipWorld) { w.reverse("8.8.4.4") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			facts := w.seed("8.8.4.4", c.mod)
			if c.after != nil {
				c.after(w)
			}
			rec := w.record("8.8.4.4")
			facts.check(t, rec)
			if len(rec.failures()) != 0 || !slices.Equal(rec.keys, ipDefaultKeys) {
				t.Errorf("record %s", rec.raw)
			}
			for _, k := range ipSourceKeys(false) {
				if _, ok := rec.m[k]; !ok {
					t.Errorf("%s is missing", k)
				}
			}
		})
	}
}

// ipFailureCase is one way a source fails for the one address of a call: how the fake is broken, the
// failure entry the record should hold, and the keys that should be null.
type ipFailureCase struct {
	name, source  string
	codes         []string // the codes the failure may have
	transient     bool
	quota         bool     // a spent quota: listed in the record, and the call still succeeds
	timeout       string   // --timeout, "" for none
	keys          []string // null in the record
	alsoDependent []string // keys of other sources that depend on the failing one, which are not compared
	breakIt       func(w *ipWorld)
}

// run breaks the source, looks the address up and checks the record.
func (c ipFailureCase) run(t *testing.T) {
	t.Helper()
	const addr = "8.8.4.4"
	w := newIPWorld(t)
	facts := w.seed(addr)
	w.sealProbes([]string{addr})
	c.breakIt(w)
	args := []string{addr}
	if c.timeout != "" {
		args = append(args, "--timeout", c.timeout)
	}
	var rec ipRecord
	if c.quota {
		rec = w.record(args...)
	} else {
		env, _ := w.partial(args...)
		if len(env.Records) != 1 {
			t.Fatalf("records %s", w.h.stdout.String())
		}
		rec = env.Records[0]
	}
	f := rec.failureOf(c.source)
	if !slices.Contains(c.codes, f.Code) || f.Transient != c.transient || f.Quota != c.quota || f.Message == "" {
		t.Errorf("failure %+v, want code in %v, transient %v, quota %v", f, c.codes, c.transient, c.quota)
	}
	if len(c.alsoDependent) == 0 && len(rec.failures()) != 1 {
		t.Errorf("failures %+v", rec.failures())
	}
	for _, k := range c.keys {
		if !rec.isNull(k) {
			t.Errorf("%s = %v, want null", k, rec.m[k])
		}
	}
	facts.check(t, rec, append(slices.Clone(c.keys), c.alsoDependent...)...)
	if !slices.Equal(rec.keys, ipDefaultKeys) {
		t.Errorf("keys %v", rec.keys)
	}
}

// ipHTTPFailures are the ways the four HTTP sources fail: each source with each failure.
func ipHTTPFailures() []ipFailureCase {
	idbKeys := []string{"internetdb_ports", "internetdb_hostnames", "internetdb_tags", "internetdb_cpes", "internetdb_vulns"}
	rdapKeys := []string{"rdap_netblock", "rdap_org", "rdap_registry"}
	var out []ipFailureCase
	for _, s := range []struct {
		label, source string
		keys          []string
		malformed     string
		set           func(w *ipWorld, h http.HandlerFunc)
	}{
		{"internetdb", "internetdb", idbKeys, `{"ports":[`, func(w *ipWorld, h http.HandlerFunc) { w.idb.setAll(h) }},
		{"ripestat", "ripestat", []string{"geo_country", "geo_city"}, `{"data":`, func(w *ipWorld, h http.HandlerFunc) { w.geo.setAll(h) }},
		{"hackertarget", "hackertarget", []string{"reverse_ip", "reverse_ip_count"}, "<html>Bad gateway</html>", func(w *ipWorld, h http.HandlerFunc) { w.ht.setAll(h) }},
		{"rdap registry", "rdap", rdapKeys, `{"startAddress":`, func(w *ipWorld, h http.HandlerFunc) { w.rdap[hostARIN].setAll(h) }},
		{"rdap bootstrap", "rdap", rdapKeys, `{"services":`, func(w *ipWorld, h http.HandlerFunc) { w.iana.setAll(h) }},
	} {
		for _, m := range []struct {
			name      string
			codes     []string
			timeout   string
			handler   http.HandlerFunc
			malformed bool
		}{
			{"429", []string{"RATE_LIMITED"}, "", ipStatus(429), false},
			{"500", []string{"UPSTREAM_ERROR"}, "", ipStatus(500), false},
			{"malformed", []string{"UPSTREAM_ERROR"}, "", nil, true},
			{"truncated", []string{"UPSTREAM_ERROR", "NETWORK_ERROR"}, "", ipTruncated(), false},
			{"hang", []string{"TIMEOUT"}, "800ms", ipHang(), false},
		} {
			c := ipFailureCase{name: s.label + " " + m.name, source: s.source, codes: m.codes, transient: true, timeout: m.timeout, keys: s.keys}
			h := m.handler
			if m.malformed {
				h = ipReply(200, s.malformed)
			}
			c.breakIt = func(w *ipWorld) { s.set(w, h) }
			if s.source == "hackertarget" && m.name == "429" {
				c.quota, c.transient = true, false // HackerTarget's 429 is its spent quota
			}
			out = append(out, c)
		}
	}
	return out
}

// ipDNSFailures are the ways Team Cymru's lookup and the PTR lookup fail. The owner's failure also
// leaves the provider and the reverse-IP names, which depend on it, out of what is compared.
func ipDNSFailures() []ipFailureCase {
	const addr = "8.8.4.4"
	var out []ipFailureCase
	for _, s := range []struct {
		source        string
		keys, depends []string
		name          string
	}{
		{"cymru", []string{"asn", "as_name", "as_prefix"}, []string{"provider", "provider_class", "reverse_ip", "reverse_ip_count"}, cymruOriginName(addr)},
		{"ptr", []string{"ptr"}, nil, reverseName(addr)},
	} {
		out = append(out,
			ipFailureCase{name: s.source + " SERVFAIL", source: s.source, codes: []string{"NETWORK_ERROR"}, transient: true, keys: s.keys,
				alsoDependent: s.depends, breakIt: func(w *ipWorld) { w.dns.Rcode(s.name, int(mdns.RcodeServerFailure)) }},
			// A query nobody answers fails by the resolver's own timeout or the call's, whichever is first.
			ipFailureCase{name: s.source + " no answer", source: s.source, codes: []string{"TIMEOUT", "NETWORK_ERROR"}, transient: true, timeout: "800ms",
				keys: s.keys, alsoDependent: s.depends, breakIt: func(w *ipWorld) { w.dns.Drop(s.name) }})
	}
	return out
}

// A source that fails (a 429, a 500, a body that is malformed or cut short, no answer by the
// deadline, a DNS error) gives a failure entry in the record and nothing else: its keys are null and
// every other source's keys are whole.
func TestIP_AFailingSourceNullsOnlyItsOwnKeys(t *testing.T) {
	t.Parallel()
	for _, c := range append(ipHTTPFailures(), ipDNSFailures()...) {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			c.run(t)
		})
	}
}

// A source that fails for one address of a batch leaves the others whole.
func TestIP_AFailureForOneAddressLeavesTheOthersWhole(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	facts := map[string]ipFacts{}
	for _, a := range []string{"8.8.4.4", "8.8.4.5", "8.8.4.6", "8.8.4.7"} {
		facts[a] = w.seed(a)
	}
	w.sealProbes([]string{"8.8.4.4", "8.8.4.5", "8.8.4.6", "8.8.4.7"})
	w.idb.set("8.8.4.5", ipStatus(500))
	env, _ := w.partial("8.8.4.4/30")
	if got := env.addresses(); !slices.Equal(got, []string{"8.8.4.4", "8.8.4.5", "8.8.4.6", "8.8.4.7"}) {
		t.Fatalf("addresses %v", got)
	}
	for _, r := range env.Records {
		if r.address() == "8.8.4.5" {
			if f := r.failureOf("internetdb"); f.Code != "UPSTREAM_ERROR" || !f.Transient || !r.isNull("internetdb_ports") {
				t.Errorf("8.8.4.5: %s", r.raw)
			}
			facts[r.address()].check(t, r, "internetdb_ports", "internetdb_hostnames", "internetdb_tags", "internetdb_cpes", "internetdb_vulns")
			continue
		}
		if len(r.failures()) != 0 {
			t.Errorf("%s: %s", r.address(), r.raw)
		}
		facts[r.address()].check(t, r)
	}
}

// HackerTarget is asked for a dedicated address, a cloud (hyperscaler) address included, and not
// for an address of shared provider infrastructure, whose keys are null with no failure.
func TestIP_HackerTargetIsAskedOnlyForAddressesThatAreNotShared(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	shared := w.seed("104.16.0.1", ipCloudflare...)
	dedicated := w.seed("8.8.4.4")
	aws := w.seed("52.0.0.1", ipAWS...)
	do := w.seed("159.65.0.1", ipDigitalOcn...)
	w.sealProbes([]string{"104.16.0.1", "8.8.4.4", "52.0.0.1", "159.65.0.1"})
	env := w.lookup("104.16.0.1", "8.8.4.4", "52.0.0.1", "159.65.0.1")
	for i, f := range []ipFacts{shared, dedicated, aws, do} {
		f.check(t, env.Records[i])
		if len(env.Records[i].failures()) != 0 {
			t.Errorf("%s: %s", f.Addr, env.Records[i].raw)
		}
	}
	if n := w.ht.countFor("104.16.0.1"); n != 0 {
		t.Errorf("HackerTarget was asked %d times about the Cloudflare address", n)
	}
	for _, a := range []string{"8.8.4.4", "52.0.0.1", "159.65.0.1"} {
		if n := w.ht.countFor(a); n != 1 {
			t.Errorf("HackerTarget was asked %d times about %s", n, a)
		}
	}
}

// HackerTarget's names are cleaned, without repeats and sorted; the first 100 are returned with the
// total count.
func TestIP_ReverseIPNamesAreCleanedSortedAndCapped(t *testing.T) {
	t.Parallel()
	t.Run("cleaned", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.seed("8.8.4.4", func(f *ipFacts) { f.Reverse = nil })
		w.reverse("8.8.4.4", "WWW.Example.org", "www.example.org", "", "  b.example.org  ", "a.example.org.")
		rec := w.record("8.8.4.4")
		if got := rec.strs("reverse_ip"); !slices.Equal(got, []string{"a.example.org", "b.example.org", "www.example.org"}) || rec.m["reverse_ip_count"] != float64(3) {
			t.Errorf("record %s", rec.raw)
		}
	})
	t.Run("150 names", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.seed("8.8.4.4", func(f *ipFacts) { f.Reverse = nil })
		var lines, sorted []string
		for i := 150; i >= 1; i-- {
			lines = append(lines, fmt.Sprintf("n%03d.example.org", i))
			sorted = append([]string{fmt.Sprintf("n%03d.example.org", i)}, sorted...)
		}
		w.reverse("8.8.4.4", lines...)
		rec := w.record("8.8.4.4")
		if got := rec.strs("reverse_ip"); !slices.Equal(got, sorted[:100]) || rec.m["reverse_ip_count"] != float64(150) {
			t.Errorf("reverse_ip has %d names (count %v), want the first 100 of 150", len(got), rec.m["reverse_ip_count"])
		}
	})
}

// Geolocation: a country of "?" and a city of "" are null, and with several locations the one that
// covers the most is used.
func TestIP_GeolocationFollowsTheMostCoveredLocation(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name          string
		locs          []ipLoc
		country, city any
	}{
		{"unknown country", []ipLoc{{"?", "", 100}}, nil, nil},
		{"no city", []ipLoc{{"AU", "", 100}}, "AU", nil},
		{"the most covered", []ipLoc{{"US", "Austin", 20}, {"AU", "Sydney", 80}, {"NZ", "Auckland", 0}}, "AU", "Sydney"},
		{"no locations", nil, nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			w.seed("8.8.4.4", func(f *ipFacts) { f.Country, f.City = "", "" })
			w.locate("8.8.4.4", c.locs...)
			rec := w.record("8.8.4.4", "--fields", "geo_country,geo_city")
			if rec.m["geo_country"] != c.country || rec.m["geo_city"] != c.city || len(rec.failures()) != 0 {
				t.Errorf("record %s", rec.raw)
			}
		})
	}
}

// The registered netblock is the CIDR when the range is exactly one, and start-end otherwise; the
// registry is the one that answered, a referral being followed.
func TestIP_RDAPNetblockRegistryAndReferrals(t *testing.T) {
	t.Parallel()
	t.Run("a CIDR", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.netblock(hostARIN, "8.8.4.0", "8.8.4.255", "NET-A", "Example Org Pty Ltd")
		rec := w.record("8.8.4.4", "--fields", "rdap_netblock,rdap_org,rdap_registry")
		if rec.str("rdap_netblock") != "8.8.4.0/24" || rec.str("rdap_org") != "Example Org Pty Ltd" || rec.str("rdap_registry") != "arin" {
			t.Errorf("record %s", rec.raw)
		}
	})
	t.Run("a range that is not a CIDR, at another registry", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.route("8.0.0.0/8", hostRIPE)
		w.netblock(hostRIPE, "8.8.4.0", "8.8.4.200", "NET-R", "Rip Org BV")
		rec := w.record("8.8.4.4", "--fields", "rdap_netblock,rdap_org,rdap_registry")
		if rec.str("rdap_netblock") != "8.8.4.0-8.8.4.200" || rec.str("rdap_org") != "Rip Org BV" || rec.str("rdap_registry") != "ripe" {
			t.Errorf("record %s", rec.raw)
		}
		if w.rdap[hostARIN].count() != 0 {
			t.Errorf("ARIN was asked: %v", w.rdap[hostARIN].requests())
		}
	})
	t.Run("a referral is followed", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.refer(hostARIN, hostAPNIC, "8.8.4.4")
		w.netblock(hostAPNIC, "8.8.4.0", "8.8.4.255", "NET-AP", "Apnic Org")
		rec := w.record("8.8.4.4", "--fields", "rdap_netblock,rdap_org,rdap_registry")
		if rec.str("rdap_org") != "Apnic Org" || rec.str("rdap_registry") != "apnic" || len(rec.failures()) != 0 {
			t.Errorf("record %s", rec.raw)
		}
		if w.rdap[hostARIN].count() != 1 || w.rdap[hostAPNIC].count() != 1 {
			t.Errorf("ARIN %v, APNIC %v", w.rdap[hostARIN].requests(), w.rdap[hostAPNIC].requests())
		}
	})
	t.Run("an address no registry holds", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		rec := w.record("8.8.4.4", "--fields", "rdap_netblock,rdap_org,rdap_registry")
		if !rec.isNull("rdap_netblock") || !rec.isNull("rdap_org") || !rec.isNull("rdap_registry") || len(rec.failures()) != 0 {
			t.Errorf("record %s", rec.raw)
		}
	})
}

// ---- default contact ----

// By default only third parties and DNS resolvers are contacted: the address itself receives
// nothing, whatever InternetDB says is open on it, and every HTTP request is to a source host
// (checked by each fake as it answers).
func TestIP_DefaultModeNeverContactsTheAddress(t *testing.T) { // mutation target
	t.Parallel()
	w := newIPWorld(t)
	w.dns.A("www.example.com", "9.9.9.9", "2606:4700::1")
	w.dns.A("intranet.example.com", "10.1.1.1")
	addrs := []string{"8.8.4.4", "9.9.9.9", "2606:4700::1", "10.1.1.1"}
	w.seed("8.8.4.4", func(f *ipFacts) { f.Ports = []int{22, 443, 2222} })
	w.seed("9.9.9.9")
	w.seed("2606:4700::1")
	w.seed("10.1.1.1")
	// Every kind of target the probes could reach: a web server on each web port, a TLS one on each
	// TLS port, a banner on 22 and a closed port among the sealed ones. None may see a connection.
	for _, a := range addrs {
		for _, p := range ipTLSPorts {
			w.serveTLS(a, p, http.NotFoundHandler())
		}
		for _, p := range ipWebPorts {
			if !slices.Contains(ipTLSPorts, p) {
				w.serveHTTP(a, p, http.NotFoundHandler())
			}
		}
		w.listen(a, 22, "SSH-2.0-OpenSSH_9.6\r\n")
		w.closedPort(a, 2323)
	}
	w.sealProbes(addrs, 2222)
	for _, args := range [][]string{
		{"8.8.4.4", "www.example.com", "intranet.example.com"},
		{"8.8.4.4", "www.example.com", "intranet.example.com", "--fields", "all"},
		{"8.8.4.4", "--fields", "internetdb_ports,ptr"},
	} {
		w.lookup(args...)
		if c := w.contacted(); len(c) != 0 {
			t.Fatalf("%v: connections to %v", args, c)
		}
	}
	if got := w.targetAt("8.8.4.4", 22); got.connections() != 0 || got.received() != 0 {
		t.Errorf("the SSH banner target saw %d connections and %d bytes", got.connections(), got.received())
	}
	if w.h.network() != 0 {
		t.Error("a network canary was hit")
	}
	if w.httpRequests() == 0 {
		t.Error("no source was asked")
	}
	for _, ty := range []string{"MX", "NS", "SOA", "CAA", "SRV", "CNAME"} {
		if q := w.dns.Queried(ty); len(q) != 0 {
			t.Errorf("the public resolvers were asked %s for %v", ty, q)
		}
	}
	for _, n := range w.dns.Queried("TXT") {
		if !strings.HasSuffix(n, ".cymru.com") {
			t.Errorf("a TXT query for %s", n)
		}
	}
	if w.local.Total() != 0 {
		t.Errorf("this machine's resolver was asked %v", dnsNames(w.local))
	}
	w.neverSent("10.1.1.1")
}

// ---- --fields ----

// Only the sources the selected keys need are asked, with the sources those depend on: the provider
// and the reverse-IP names need Team Cymru, and nothing else is.
func TestIP_FieldsAskOnlyTheSourcesTheyNeed(t *testing.T) {
	t.Parallel()
	const addr = "8.8.4.4"
	type asked struct{ cymru, ptr, rdap, geo, idb, ht bool }
	for _, c := range []struct {
		fields string
		want   asked
	}{
		{"asn", asked{cymru: true}},
		{"as_prefix", asked{cymru: true}},
		{"as_name", asked{cymru: true}},
		{"provider", asked{cymru: true}},
		{"provider_class", asked{cymru: true}},
		{"rdap_org", asked{rdap: true}},
		{"rdap_netblock,rdap_registry", asked{rdap: true}},
		{"ptr", asked{ptr: true}},
		{"geo_country", asked{geo: true}},
		{"geo_city,geo_country", asked{geo: true}},
		{"internetdb_vulns", asked{idb: true}},
		{"internetdb_ports,internetdb_tags", asked{idb: true}},
		{"reverse_ip", asked{cymru: true, ht: true}},
		{"reverse_ip_count", asked{cymru: true, ht: true}},
		{"asn,ptr", asked{cymru: true, ptr: true}},
	} {
		t.Run(c.fields, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			facts := w.seed(addr)
			w.sealProbes([]string{addr})
			rec := w.record(addr, "--fields", c.fields)
			selected := strings.Split(c.fields, ",")
			if want := ipExpectKeys(selected...); !slices.Equal(rec.keys, want) {
				t.Errorf("keys %v, want %v", rec.keys, want)
			}
			var skip []string
			for _, k := range ipSourceKeys(false) {
				if !slices.Contains(selected, k) {
					skip = append(skip, k)
				}
			}
			facts.check(t, rec, skip...)
			got := asked{
				cymru: w.dns.Count(cymruOriginName(addr), "TXT") > 0,
				ptr:   w.dns.Count(reverseName(addr), "PTR") > 0,
				rdap:  w.rdapRequests() > 0,
				geo:   w.geo.count() > 0,
				idb:   w.idb.count() > 0,
				ht:    w.ht.count() > 0,
			}
			if got != c.want {
				t.Errorf("asked %+v, want %+v", got, c.want)
			}
			if w.local.Total() != 0 || len(w.contacted()) != 0 {
				t.Errorf("local queries %v, connections %v", dnsNames(w.local), w.contacted())
			}
		})
	}
}

// --fields "" asks nothing and returns the keys that are always there; naming a key is how to ask
// for it, and --fields all is what no --fields gives.
func TestIP_FieldsEmptyAndAll(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{"--fields", ""}, {"--fields="}} {
			w := newIPWorld(t)
			w.seed("8.8.4.4")
			w.sealProbes([]string{"8.8.4.4"})
			rec := w.record(append([]string{"8.8.4.4"}, args...)...)
			if want := []string{"address", "hostnames", "kind", "failures"}; !slices.Equal(rec.keys, want) {
				t.Errorf("%v: keys %v, want %v", args, rec.keys, want)
			}
			w.untouched()
		}
	})
	t.Run("all", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.seed("8.8.4.4")
		w.seed("10.0.0.1")
		w.sealProbes([]string{"8.8.4.4", "10.0.0.1"})
		if code := w.runJSON("8.8.4.4", "10.0.0.1"); code != 0 {
			t.Fatalf("exit %d", code)
		}
		without := w.h.stdout.String()
		if code := w.runJSON("8.8.4.4", "10.0.0.1", "--fields", "all"); code != 0 {
			t.Fatalf("exit %d", code)
		}
		if w.h.stdout.String() != without {
			t.Errorf("--fields all differs from no --fields:\n%s\n%s", w.h.stdout.String(), without)
		}
		for _, r := range w.h.ipEnvelope().Records {
			if !slices.Equal(r.keys, ipAllKeys(false)) {
				t.Errorf("keys %v", r.keys)
			}
		}
	})
}

// The keys come in the order of the record, not the order --fields names them, and a key may be
// named twice.
func TestIP_FieldsKeepTheRecordOrder(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.seed("8.8.4.4")
	rec := w.record("8.8.4.4", "--fields", "geo_city,asn,ptr,asn,as_name")
	if want := []string{"address", "hostnames", "kind", "asn", "as_name", "ptr", "geo_city", "failures"}; !slices.Equal(rec.keys, want) {
		t.Errorf("keys %v, want %v", rec.keys, want)
	}
}

// An unknown name, and an --active key without --active, exit 2 with every problem and the valid
// names in the hint, before anything is asked.
func TestIP_FieldsProblemsAreReportedTogether(t *testing.T) {
	t.Parallel()
	t.Run("unknown and active-only", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		f := w.h.failed(w.runJSON("8.8.4.4", "--fields", "asn,bogus,ports,tls"), 2, true)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "bogus") || !strings.Contains(f.msg, "ports") || !strings.Contains(f.msg, "--active") {
			t.Errorf("%+v", f)
		}
		for _, name := range ipSourceKeys(false) {
			if !strings.Contains(f.hint, name) {
				t.Errorf("the hint leaves out %s: %s", name, f.hint)
			}
		}
		if got := f.inputOf("fields"); !slices.Contains(got, "bogus") || !slices.Contains(got, "ports") || !slices.Contains(got, "tls") || slices.Contains(got, "asn") {
			t.Errorf("input %v", f.input)
		}
		w.untouched()
	})
	t.Run("an unknown name under --active", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		f := w.h.failed(w.runJSON("8.8.4.4", "--active", "--fields", "bogus"), 2, true)
		for _, name := range ipSourceKeys(true) {
			if !strings.Contains(f.hint, name) {
				t.Errorf("the hint leaves out %s: %s", name, f.hint)
			}
		}
		w.untouched()
	})
	t.Run("with the other problems", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		f := w.h.failed(w.runJSON("https://example.com/x", "--fields", "bogus", "--timeout", "soon"), 2, true)
		if !strings.Contains(f.msg, "bogus") || !strings.Contains(f.msg, "example.com") || !strings.Contains(f.msg, "timeout") {
			t.Errorf("%+v", f)
		}
		w.untouched()
	})
}

// Under --active the shared check (Team Cymru's owner of the address) is made whatever --fields
// selects, and not in the default mode.
func TestIP_ActiveFieldsStillRunTheSharedCheck(t *testing.T) {
	t.Parallel()
	const addr = "104.16.0.1"
	for _, active := range []bool{true, false} {
		w := newIPWorld(t)
		w.seed(addr, ipCloudflare...)
		w.sealProbes([]string{addr})
		args := []string{addr, "--fields", "geo_country"}
		if active {
			args = append(args, "--active")
		}
		rec := w.record(args...)
		if want := ipExpectKeys("geo_country"); !slices.Equal(rec.keys, want) || rec.str("geo_country") != "AU" {
			t.Errorf("active=%v: record %s", active, rec.raw)
		}
		if got := w.dns.Count(cymruOriginName(addr), "TXT") > 0; got != active {
			t.Errorf("active=%v: the shared check was made: %v", active, got)
		}
		if c := w.contacted(); len(c) != 0 {
			t.Errorf("active=%v: connections to %v (a shared address is never contacted)", active, c)
		}
	}
}

// ---- --json ----

// The envelope has exactly its keys in order, meta.hint is null whatever the outcome, and each
// meta.errors entry has the five keys of an error with its input as documented: the inputs as given
// that named it and, for an address that failed, the address.
func TestIP_EnvelopeKeysAndErrorEntries(t *testing.T) {
	t.Parallel()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.seed("8.8.4.4")
		w.seed("1.1.1.1")
		env := w.lookup("8.8.4.4", "1.1.1.1")
		if env.Meta.Count != 2 || len(env.Meta.Errors) != 0 || len(env.Meta.Warnings) != 0 || env.Meta.Hint != nil {
			t.Errorf("meta %+v", env.Meta)
		}
		out := w.h.stdout.String()
		if !strings.HasPrefix(out, `{"data":[{"address":"8.8.4.4","hostnames":[],"kind":"public","asn":64500,`) ||
			!strings.HasSuffix(out, `],"meta":{"count":2,"errors":[],"warnings":[],"hint":null}}`+"\n") {
			t.Errorf("stdout %s", out)
		}
	})
	t.Run("nothing selected", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.lookup("8.8.4.4", "--fields", "")
		if got, want := w.h.stdout.String(), `{"data":[{"address":"8.8.4.4","hostnames":[],"kind":"public","failures":[]}],"meta":{"count":1,"errors":[],"warnings":[],"hint":null}}`+"\n"; got != want {
			t.Errorf("stdout %s\nwant   %s", got, want)
		}
	})
	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.seed("8.8.4.4")
		w.seed("8.8.4.5")
		w.idb.set("8.8.4.5", ipStatus(500))
		env, f := w.partial("8.8.4.4/31", "https://example.com/x", "nx.example.com", "--fields", "internetdb_ports")
		if env.Meta.Count != 1 || !slices.Equal(env.addresses(), []string{"8.8.4.4"}) || env.Meta.Hint != nil || len(env.Meta.Warnings) != 0 {
			t.Errorf("data %v, meta %+v", env.addresses(), env.Meta)
		}
		checkErrorKeys(t, w.h.stdout.Bytes())
		checkErrorEntries(t, env.Meta.Errors)
		// The retry command is for the address, not the CIDR that gave it, with the flags given.
		if !f.transient || !strings.Contains(f.hint, "nyx ip 8.8.4.5") || strings.Contains(f.hint, "8.8.4.4/31") ||
			!strings.Contains(f.hint, "--fields internetdb_ports") || !strings.Contains(f.hint, "--json") {
			t.Errorf("error %+v", f)
		}
	})
}

// checkErrorKeys fails the test unless every entry of the envelope's meta.errors has the five keys
// of an error, in order.
func checkErrorKeys(t *testing.T, envelope []byte) {
	t.Helper()
	var raw struct {
		Meta struct {
			Errors []json.RawMessage `json:"errors"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(envelope, &raw); err != nil {
		t.Fatal(err)
	}
	for _, e := range raw.Meta.Errors {
		if got := keysOf(t, e); !slices.Equal(got, []string{"error", "code", "hint", "input", "transient"}) {
			t.Errorf("error keys %v: %s", got, e)
		}
	}
}

// checkErrorEntries checks the three entries of the call of TestIP_EnvelopeKeysAndErrorEntries: an
// invalid input and an input with no address name only the input, and an address that failed also
// names itself and the CIDR that gave it.
func checkErrorEntries(t *testing.T, errs []ipMetaError) {
	t.Helper()
	byCode := map[string]ipMetaError{}
	for _, e := range errs {
		byCode[e.Code] = e
	}
	if len(errs) != 3 || len(byCode) != 3 {
		t.Fatalf("meta.errors %+v", errs)
	}
	if e := byCode["INVALID_INPUT"]; !slices.Equal(e.inputs(), []string{"https://example.com/x"}) || e.address() != "" || e.Transient || len(e.Input) != 1 {
		t.Errorf("invalid input: %+v", e)
	}
	if e := byCode["NOT_FOUND"]; !slices.Equal(e.inputs(), []string{"nx.example.com"}) || e.address() != "" || e.Transient || len(e.Input) != 1 {
		t.Errorf("not found: %+v", e)
	}
	if e := byCode["UPSTREAM_ERROR"]; !slices.Equal(e.inputs(), []string{"8.8.4.4/31"}) || e.address() != "8.8.4.5" || !e.Transient || len(e.Input) != 2 {
		t.Errorf("failed address: %+v", e)
	}
}
