package config_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
)

// load uses only the supplied environment, keeping config tests independent and parallel-safe.
func load(t *testing.T, env config.Env, cfgPath string, args ...string) (config.Settings, error) {
	t.Helper()
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return config.Load(fs, cfgPath, env)
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Defaults.
func TestDefaults(t *testing.T) {
	t.Parallel()
	s, err := load(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Ports) != 105 {
		t.Errorf("default ports = %d, want 105 (the nmap top 100 plus five risky ports)", len(s.Ports))
	}
	if got := config.FormatPorts(s.RiskyPorts); got != "21,23,445,1433,1521,3306,3389,5432,5900,6379,9200,11211,27017" {
		t.Errorf("risky ports = %s", got)
	}
	if s.Concurrency != 10 || s.Rate.PerHost != 5 || s.Rate.PerSource != 1 || s.Rate.DNS != 50 {
		t.Errorf("concurrency/rates = %d %+v", s.Concurrency, s.Rate)
	}
	if s.Crawl.MaxDepth != 2 || s.Crawl.MaxPages != 100 {
		t.Errorf("crawl = %+v", s.Crawl)
	}
	if s.OutputDir != "." || s.NetblockLimit != 4096 {
		t.Errorf("output_dir=%q netblock_limit=%d", s.OutputDir, s.NetblockLimit)
	}
	if s.SensitivePaths != "" || s.Wordlist != "" {
		t.Errorf("file defaults should be empty (built-in): %q %q", s.SensitivePaths, s.Wordlist)
	}
}

// Flags win over the file for a scalar and a list, and a NYX_* variable changes nothing.
func TestPrecedence(t *testing.T) {
	t.Parallel()
	cfg := writeFile(t, "concurrency: 2\nports: [80, 443]\n")

	s, err := load(t, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency != 2 || config.FormatPorts(s.Ports) != "80,443" {
		t.Fatalf("file: %d %v", s.Concurrency, s.Ports)
	}

	env := config.Env{"NYX_CONCURRENCY=3", "NYX_PORTS=8080,8081"}
	s, err = load(t, env, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency != 2 || config.FormatPorts(s.Ports) != "80,443" {
		t.Fatalf("env: %d %v: a NYX_* variable was read", s.Concurrency, s.Ports)
	}

	s, err = load(t, env, cfg, "--concurrency", "7", "--ports", "9000,9001-9003")
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency != 7 || config.FormatPorts(s.Ports) != "9000-9003" {
		t.Fatalf("flag: %d %v", s.Concurrency, s.Ports)
	}
}

// Settings/keys ignore environment values; only config-location variables are read. This
// process-environment test cannot run in parallel.
func TestLoadReadsNoSettingFromTheEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NYX_CONCURRENCY", "3")
	t.Setenv("NYX_KEYS_SHODAN", "process-key")
	t.Setenv("HOME", home)
	s, err := config.Load(nil, "", config.Env{"NYX_RATE_DNS=9", "NYX_KEYS_CENSYS=given-key", "NVD_API_KEY=nvd-key"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency != config.Defaults().Concurrency || s.Rate.DNS != config.Defaults().Rate.DNS {
		t.Errorf("concurrency %d, rate.dns %v: want the defaults", s.Concurrency, s.Rate.DNS)
	}
	if got := s.KeyValues(); len(got) != 0 {
		t.Errorf("keys = %v, want none", got)
	}
	if got := config.DefaultConfigPath(config.Env{"HOME=/given"}); got != "/given/.config/nyx/config.yaml" {
		t.Errorf("DefaultConfigPath = %q", got)
	}
	if s, _ := config.Load(nil, "", nil); s.OutputDir != "." {
		t.Errorf("with no HOME given, output_dir = %q", s.OutputDir)
	}
}

func TestNestedSettings(t *testing.T) {
	t.Parallel()
	cfg := writeFile(t, "rate:\n  per_host: 2\ncrawl:\n  max_depth: 4\n")
	s, err := load(t, nil, cfg, "--rate-dns", "10", "--crawl-pages", "7")
	if err != nil {
		t.Fatal(err)
	}
	if s.Rate.PerHost != 2 || s.Rate.DNS != 10 || s.Crawl.MaxDepth != 4 || s.Crawl.MaxPages != 7 {
		t.Fatalf("%+v %+v", s.Rate, s.Crawl)
	}
}

// Keys from the file only; never a flag or a variable; never formatted.
func TestKeys(t *testing.T) {
	t.Parallel()
	cfg := writeFile(t, "keys:\n  shodan: filesecret123\n  censys: filesecret456\n")
	s, err := load(t, config.Env{"NYX_KEYS_CENSYS=envsecret789", "NYX_KEYS_CHAOS=envsecret000"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Keys["shodan"].Reveal() != "filesecret123" || s.Keys["censys"].Reveal() != "filesecret456" {
		t.Fatalf("keys not loaded: %v", s.Keys)
	}
	if _, ok := s.Keys["chaos"]; ok {
		t.Errorf("NYX_KEYS_CHAOS was read: %v", s.Keys)
	}
	for _, out := range []string{
		fmt.Sprintf("%v", s.Keys["shodan"]), fmt.Sprintf("%s", s.Keys["shodan"]),
		fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprint(s.Keys),
	} {
		if strings.Contains(out, "filesecret123") || strings.Contains(out, "filesecret456") {
			t.Errorf("secret leaked in %q", out)
		}
	}
	b, _ := json.Marshal(s) //nolint:musttag // Settings has no JSON form; this checks that a Secret stays redacted if one is ever marshalled
	if strings.Contains(string(b), "filesecret123") || strings.Contains(string(b), "filesecret456") {
		t.Errorf("secret leaked in JSON %s", b)
	}
	kv := s.KeyValues()
	if len(kv) != 2 {
		t.Errorf("KeyValues = %v", kv)
	}

	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	fs.VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, "key") {
			t.Errorf("flag --%s exists; keys must not be settable by flag", f.Name)
		}
	})
}

// Invalid config values name the key and the value.
func TestValidation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	relPaths := writeFile(t, "- path: /ok\n  signature: x\n- path: admin/.env\n  signature: x\n")
	cases := []struct {
		name, file string
		env        config.Env
		args       []string
		wantKey    string
		wantVal    string
	}{
		{"port high", "ports: [70000]\n", nil, nil, "ports", "70000"},
		{"port zero flag", "", nil, []string{"--ports", "0"}, "ports", "0"},
		{"port range reversed", "", nil, []string{"--ports", "90-80"}, "ports", "90-80"},
		{"risky port", "", nil, []string{"--risky-ports", "99999"}, "risky_ports", "99999"},
		{"concurrency zero", "concurrency: 0\n", nil, nil, "concurrency", "0"},
		{"concurrency text", "concurrency: lots\n", nil, nil, "concurrency", "lots"},
		{"rate negative", "", nil, []string{"--rate-per-host", "-1"}, "rate.per_host", "-1"},
		{"rate dns zero", "rate:\n  dns: 0\n", nil, nil, "rate.dns", "0"},
		{"unknown key", "concurency: 3\n", nil, nil, "concurency", "concurency"},
		{"unreadable wordlist", "", nil, []string{"--wordlist", filepath.Join(dir, "nope.txt")}, "wordlist", "nope.txt"},
		{"wordlist is a directory", "", nil, []string{"--wordlist", dir}, "wordlist", dir},
		{"unreadable paths", "", nil, []string{"--sensitive-paths", filepath.Join(dir, "nope.yaml")}, "sensitive_paths", "nope.yaml"},
		{"relative sensitive path", "", nil, []string{"--sensitive-paths", relPaths}, "sensitive_paths", "admin/.env"},
		{"crawl depth negative", "", nil, []string{"--crawl-depth", "-2"}, "crawl.max_depth", "-2"},
		{"netblock zero", "", nil, []string{"--netblock-limit", "0"}, "netblock_limit", "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			cfg := ""
			if c.file != "" {
				cfg = writeFile(t, c.file)
			}
			_, err := load(t, c.env, cfg, c.args...)
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), c.wantKey) || !strings.Contains(err.Error(), c.wantVal) {
				t.Errorf("error %q should name %q and %q", err, c.wantKey, c.wantVal)
			}
		})
	}
}

func TestExplicitConfigMissing(t *testing.T) {
	t.Parallel()
	if _, err := load(t, nil, filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("explicit missing config file should be an error")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	t.Parallel()
	if got := config.DefaultConfigPath(config.Env{"XDG_CONFIG_HOME=/xdg", "HOME=/home/u"}); got != "/xdg/nyx/config.yaml" {
		t.Errorf("got %s", got)
	}
	if got := config.DefaultConfigPath(config.Env{"XDG_CONFIG_HOME=", "HOME=/home/u"}); got != "/home/u/.config/nyx/config.yaml" {
		t.Errorf("got %s", got)
	}
}

func TestDefaultConfigPathWithoutHome(t *testing.T) {
	t.Parallel()
	if got := config.DefaultConfigPath(config.Env{"XDG_CONFIG_HOME=", "HOME="}); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// It changes the working directory, so it cannot be parallel.
func TestLoadWithoutHomeIgnoresWorkingDirectoryConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".config", "nyx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".config", "nyx", "config.yaml"), []byte("not: [valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if _, err := load(t, config.Env{"XDG_CONFIG_HOME=", "HOME="}, ""); err != nil {
		t.Fatalf("config under the working directory should not be read: %v", err)
	}
}

func TestPortsRoundTrip(t *testing.T) {
	t.Parallel()
	s, err := load(t, nil, "", "--ports", "443, 21-23,80,22")
	if err != nil {
		t.Fatal(err)
	}
	if got := config.FormatPorts(s.Ports); got != "21-23,80,443" {
		t.Errorf("got %s", got)
	}
}

func TestRedactor(t *testing.T) {
	t.Parallel()
	r := config.NewRedactor("s3cr3t", "")
	if got := r.Redact("url?key=s3cr3t&x=s3cr3t"); got != "url?key=****&x=****" {
		t.Errorf("got %q", got)
	}
	m := r.Any(map[string]any{"a": "s3cr3t", "b": []any{"x s3cr3t"}, "c": 3}).(map[string]any)
	if m["a"] != "****" || m["b"].([]any)[0] != "x ****" || m["c"] != 3 {
		t.Errorf("got %v", m)
	}
	// net/http errors embed query-parameter keys percent-encoded.
	enc := config.NewRedactor("abc+def/ghi=")
	if got := enc.Redact(`Get "https://h/?key=abc%2Bdef%2Fghi%3D": timeout`); got != `Get "https://h/?key=****": timeout` {
		t.Errorf("got %q", got)
	}
	// A blank value is no key: masking it would mangle every line.
	if got := config.NewRedactor(" ", "\t").Redact("a b\tc"); got != "a b\tc" {
		t.Errorf("blank values masked: %q", got)
	}
	var nilR *config.Redactor
	if nilR.Redact("x") != "x" {
		t.Error("nil redactor must pass through")
	}
}

func newFlagSetForHelp() *pflag.FlagSet {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	return fs
}

// A leading ~ in a path setting is the home directory, not a directory named "~".
func TestHomeExpansion(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	env := config.Env{"HOME=" + home}
	cfg := writeFile(t, "output_dir: ~/engagements\n")
	s, err := load(t, env, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "engagements"); s.OutputDir != want {
		t.Errorf("output_dir = %q, want %q", s.OutputDir, want)
	}
	for _, c := range []struct{ in, want string }{
		{"~", home}, {"./~/x", "./~/x"}, {"~other/x", "~other/x"},
	} {
		s, err := load(t, env, "", "--output-dir="+c.in)
		if err != nil {
			t.Fatal(err)
		}
		if s.OutputDir != c.want {
			t.Errorf("--output-dir=%s: got %q, want %q", c.in, s.OutputDir, c.want)
		}
	}
}

// Numeric flags preserve invalid text for combined validation while help still names their
// numeric type.
func TestNumericFlagsTakeAnyText(t *testing.T) {
	t.Parallel()
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	for name, typ := range map[string]string{"concurrency": "integer", "netblock-limit": "integer", "rate-per-host": "float", "rate-dns": "float"} {
		if got := fs.Lookup(name).Value.Type(); got != typ {
			t.Errorf("--%s is a %s, want %s", name, got, typ)
		}
	}
	if !strings.Contains(fs.FlagUsages(), "--concurrency integer") || !strings.Contains(fs.FlagUsages(), "(default 10)") {
		t.Errorf("help:\n%s", fs.FlagUsages())
	}
	_, err := load(t, nil, "", "--concurrency", "abc", "--rate-dns", "lots", "--netblock-limit", "1e3")
	var probs clierr.Problems
	if !errors.As(err, &probs) || len(probs) != 3 {
		t.Fatalf("err = %v, want three problems", err)
	}
	for _, want := range []clierr.Problem{
		{Name: "concurrency", Value: "abc", Message: `concurrency: invalid value "abc": not an integer`},
		{Name: "rate.dns", Value: "lots", Message: `rate.dns: invalid value "lots": not a number`},
		{Name: "netblock_limit", Value: "1e3", Message: `netblock_limit: invalid value "1e3": not an integer`},
	} {
		if !slices.Contains(probs, want) {
			t.Errorf("problems %+v lack %+v", probs, want)
		}
	}
	// A good value still parses.
	if s, err := load(t, nil, "", "--concurrency", "7", "--rate-dns", "2.5"); err != nil || s.Concurrency != 7 || s.Rate.DNS != 2.5 {
		t.Errorf("%v %d %v", err, s.Concurrency, s.Rate.DNS)
	}
}

// Return loaded keys for redaction even when file/setting problems make config unusable.
func TestLoadReportsFileProblemsWithTheRest(t *testing.T) {
	t.Parallel()
	cfg := writeFile(t, "concurency: 3\nkeys:\n  shodan: filekey\n")
	s, err := load(t, nil, cfg, "--rate-dns", "-1")
	if err == nil || !strings.Contains(err.Error(), "concurency") || !strings.Contains(err.Error(), "rate.dns") {
		t.Errorf("unknown key and a bad flag: %v", err)
	}
	if s.Keys["shodan"].Reveal() != "filekey" {
		t.Error("the keys of a config file with problems are not returned")
	}
	_, err = load(t, nil, filepath.Join(t.TempDir(), "absent.yaml"), "--rate-dns", "-1")
	var probs clierr.Problems
	if !errors.As(err, &probs) || len(probs) != 2 || probs[0].Name != "config" || !strings.Contains(err.Error(), "rate.dns") {
		t.Errorf("unreadable file and a bad flag: %v", err)
	}
}

// yamlFor is a config file that sets a key, dotted or not, to val.
func yamlFor(key, val string) string {
	if section, name, ok := strings.Cut(key, "."); ok {
		return section + ":\n  " + name + ": " + val + "\n"
	}
	return key + ": " + val + "\n"
}

// Check defaults, file/flag precedence, inclusive minimums and invalid numeric input for each
// integer setting.
func TestIntSettings(t *testing.T) {
	t.Parallel()
	for _, c := range []intSetting{
		{"port_concurrency", "--port-concurrency", 100, 1, func(s config.Settings) int { return s.PortConcurrency }},
		{"storage.max_names", "--storage-max-names", 50, 1, func(s config.Settings) int { return s.Storage.MaxNames }},
		{"cert_expiry_days", "--cert-expiry-days", 30, 0, func(s config.Settings) int { return s.CertExpiryDays }},
		{"eol_warn_days", "--eol-warn-days", 90, 0, func(s config.Settings) int { return s.EOLWarnDays }},
		{"permutations.max_per_seed", "--permutations-max", 200, 1, func(s config.Settings) int { return s.Permutations.MaxPerSeed }},
		{"permutations.max_names", "--permutations-max-names", 200000, 1, func(s config.Settings) int { return s.Permutations.MaxNames }},
		{"learned_names.max_names", "--learned-names-max-names", 50000, 1, func(s config.Settings) int { return s.LearnedNames.MaxNames }},
		{"sensitive_path_max_requests", "--sensitive-path-max-requests", 50000, 1, func(s config.Settings) int { return s.SensitivePathMaxRequests }},
		{"shodan.max_hosts", "--shodan-max-hosts", 500, 1, func(s config.Settings) int { return s.Shodan.MaxHosts }},
		{"reverseip.max_domains", "--reverseip-max-domains", 100, 1, func(s config.Settings) int { return s.ReverseIP.MaxDomains }},
		{"nsreverse.max_domains", "--nsreverse-max-domains", 1000, 1, func(s config.Settings) int { return s.NSReverse.MaxDomains }},
		{"jsparse.max_scripts", "--jsparse-max-scripts", 50, 1, func(s config.Settings) int { return s.JSParse.MaxScripts }},
		{"identifier_pivot.max_queries", "--identifier-pivot-max-queries", 50, 1, func(s config.Settings) int { return s.IdentifierPivot.MaxQueries }},
	} {
		t.Run(c.key, func(t *testing.T) {
			t.Parallel()
			checkIntDefault(t, c)
			checkIntPrecedence(t, c)
			checkIntRejected(t, c)
		})
	}
}

// intSetting is a whole-number setting: its key and flag, its default and least value, and how
// to read it from Settings.
type intSetting struct {
	key, flag string
	def, min  int
	get       func(config.Settings) int
}

// checkIntDefault checks the setting's default, and that its flag's help shows it.
func checkIntDefault(t *testing.T, c intSetting) {
	t.Helper()
	if s, err := load(t, nil, ""); err != nil || c.get(s) != c.def {
		t.Fatalf("default = %d, %v; want %d", c.get(s), err, c.def)
	}
	if f := newFlagSetForHelp().Lookup(strings.TrimPrefix(c.flag, "--")); f == nil || f.DefValue != strconv.Itoa(c.def) {
		t.Errorf("%s in help = %+v, want default %d", c.flag, f, c.def)
	}
}

// checkIntPrecedence checks that the file and a flag each set the setting, the flag winning, and
// that the least value is accepted.
func checkIntPrecedence(t *testing.T, c intSetting) {
	t.Helper()
	file := writeFile(t, yamlFor(c.key, "70"))
	if s, err := load(t, nil, file); err != nil || c.get(s) != 70 {
		t.Errorf("file: %d %v", c.get(s), err)
	}
	if s, err := load(t, nil, file, c.flag, "90"); err != nil || c.get(s) != 90 {
		t.Errorf("flag over file: %d %v", c.get(s), err)
	}
	if s, err := load(t, nil, "", c.flag, strconv.Itoa(c.min)); err != nil || c.get(s) != c.min {
		t.Errorf("least value %d: %d %v", c.min, c.get(s), err)
	}
}

// checkIntRejected verifies invalid integers identify their key from either flags or YAML.
func checkIntRejected(t *testing.T, c intSetting) {
	t.Helper()
	for _, bad := range []string{strconv.Itoa(c.min - 1), "many"} {
		for from, run := range map[string]func() (config.Settings, error){
			"flag": func() (config.Settings, error) { return load(t, nil, "", c.flag, bad) },
			"file": func() (config.Settings, error) { return load(t, nil, writeFile(t, yamlFor(c.key, bad))) },
		} {
			if _, err := run(); err == nil || !strings.Contains(err.Error(), c.key) {
				t.Errorf("%s %s: error %v should name %s", from, bad, err, c.key)
			}
		}
	}
}
