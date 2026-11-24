// Package config loads settings from YAML and explicit flags, with flags taking precedence.
// Settings and API keys are never read from environment variables.
package config

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/input"
)

//go:embed builtin/wordlist.txt builtin/sensitive_paths.yaml
var builtin embed.FS

// Rate holds the request-rate limits.
type Rate struct {
	PerHost   float64 // per dialled target IP
	PerSource float64 // per third-party source
	DNS       float64 // queries/s across the public resolvers
}

// Crawl holds the crawl limits.
type Crawl struct{ MaxDepth, MaxPages int }

// JSParse holds the settings of the jsparse procedure.
type JSParse struct {
	// MaxScripts caps fetched scripts per origin without changing job keys. Fetched
	// scripts retain their slots when new URLs appear. Raising the cap admits pending
	// scripts; lowering it retires excess scripts in URL order.
	MaxScripts int
}

// Archive limits public-archive URL selection.
type Archive struct{ MaxURLs int }

// Permutations holds the subdomain-permutation settings.
type Permutations struct {
	Enabled    bool
	MaxPerSeed int
	MaxNames   int
}

// Storage holds the cloud-storage settings.
type Storage struct {
	// MaxNames bounds storage guesses per root or organisation.
	MaxNames int
}

// Shodan holds the settings of the shodan-host procedure.
type Shodan struct {
	// MaxHosts budgets address lookups, deferring excess work.
	MaxHosts int
}

// IdentifierPivot holds the settings of the identifier-pivot procedure.
type IdentifierPivot struct {
	// MaxQueries budgets identifier searches across runs.
	MaxQueries int
}

// NSReverse holds the settings of the nsreverse procedure.
type NSReverse struct {
	// MaxDomains limits domains returned for one name server or mail host. Larger results
	// are treated as shared hosting and discarded. The limit is part of the job key, so
	// changing it reruns lookups.
	MaxDomains int
}

// ReverseIP holds the settings of the reverseip procedure.
type ReverseIP struct {
	// MaxDomains limits distinct registrable domains returned for one address. Larger
	// results are treated as shared hosting and discarded. Changing the limit creates new
	// jobs.
	MaxDomains int
}

// DNSHistory holds the settings of the dnshistory procedure.
type DNSHistory struct {
	// MaxHosts budgets historical hostname lookups across runs.
	MaxHosts int
}

// OriginCheck caps origin candidates per CDN/WAF hostname. The procedure and findings share this
// setting so checked and reported candidates agree.
type OriginCheck struct {
	MaxCandidates int
}

// GitHub holds the settings of the github procedure.
type GitHub struct {
	// MaxResults versions each root's GitHub search cap, up to the service's 1,000-result
	// ceiling. Changing it reruns searches.
	MaxResults int
}

// maxGitHubResults reflects GitHub's search-result ceiling.
const maxGitHubResults = 1000

// PagedSource configures capped source pagination.
type PagedSource struct {
	// MaxPages versions jobs so increasing the cap repeats affected root queries.
	MaxPages int
}

// skipNone clears configured skipped procedures for one invocation.
const skipNone = "none"

// Settings are the validated settings for a run.
type Settings struct {
	Keys                 map[string]Secret
	Ports                []int
	RiskyPorts           []int
	SensitivePaths       string // file path; empty means the built-in list
	SensitivePathEntries []SensitivePath
	Wordlist             string // file path; empty means the built-in list
	// WordlistWords holds parsed custom or embedded names.
	WordlistWords []string
	Permutations  Permutations
	Concurrency   int
	// PortConcurrency gives slow port jobs a separate worker pool because silent ports
	// consume the full connect timeout.
	PortConcurrency int
	Rate            Rate
	Crawl           Crawl
	Archive         Archive
	Storage         Storage
	// CertExpiryDays sets the certificate-expiry warning horizon.
	CertExpiryDays int
	OutputDir      string
	NetblockLimit  int // IPv4 addresses
	Certspotter    PagedSource
	// Skip holds normalised procedure names after resolving "none". The caller validates procedure
	// existence.
	Skip      []string
	ShodanDNS PagedSource
	Censys    PagedSource
	Chaos     PagedSource
	// SensitivePathMaxRequests budgets path jobs per run.
	SensitivePathMaxRequests int
	Shodan                   Shodan
	ReverseIP                ReverseIP
	JSParse                  JSParse
	IdentifierPivot          IdentifierPivot
	GitHub                   GitHub
	DNSHistory               DNSHistory
	OriginCheck              OriginCheck
	// EOLWarnDays sets the approaching-support-end window. Zero disables approaching
	// findings.
	EOLWarnDays int
	NSReverse   NSReverse
}

// Key returns the configured API key for a source, matched case-insensitively. ok is false when
// the key is absent or empty; the value is returned either way.
func (s Settings) Key(source string) (k Secret, ok bool) {
	k = s.Keys[strings.ToLower(source)]
	return k, k.Reveal() != ""
}

// Defaults provides starting limits and rates. These values do not encode source fair-use terms
// or engagement-specific limits.
func Defaults() Settings {
	return Settings{
		Keys:            map[string]Secret{},
		Ports:           DefaultPorts(),
		RiskyPorts:      slices.Clone(defaultRisky),
		Concurrency:     10,
		PortConcurrency: 100,
		Rate:            Rate{PerHost: 5, PerSource: 1, DNS: 50},
		Crawl:           Crawl{MaxDepth: 2, MaxPages: 100},
		Archive:         Archive{MaxURLs: 20000},
		Storage:         Storage{MaxNames: 50},
		CertExpiryDays:  30,
		OutputDir:       ".",
		NetblockLimit:   4096,
		Permutations:    Permutations{Enabled: true, MaxPerSeed: 200, MaxNames: 200000},
		Certspotter:     PagedSource{MaxPages: 10},
		ShodanDNS:       PagedSource{MaxPages: 10},
		Shodan:          Shodan{MaxHosts: 500},
		ReverseIP:       ReverseIP{MaxDomains: 100},
		JSParse:         JSParse{MaxScripts: 50},
		IdentifierPivot: IdentifierPivot{MaxQueries: 50},
		GitHub:          GitHub{MaxResults: 500},
		DNSHistory:      DNSHistory{MaxHosts: 200},
		OriginCheck:     OriginCheck{MaxCandidates: 5},
		EOLWarnDays:     90,
		NSReverse:       NSReverse{MaxDomains: 1000},
		Censys:          PagedSource{MaxPages: 10},
		Chaos:           PagedSource{MaxPages: 10},

		SensitivePathMaxRequests: 50000,
	}
}

// KeyValues supplies original and trimmed key variants for redaction, covering callers that
// trim before sending.
func (s Settings) KeyValues() []string {
	var out []string
	for _, n := range slices.Sorted(maps.Keys(s.Keys)) {
		v := s.Keys[n].Reveal()
		out = append(out, v)
		if t := strings.TrimSpace(v); t != v {
			out = append(out, t)
		}
	}
	return out
}

// Parse embedded lists once for repeated help/load calls, then copy them for callers.
var (
	builtinWordlist = sync.OnceValue(func() []string {
		b, _ := builtin.ReadFile("builtin/wordlist.txt")
		list, _ := input.ParseList(bytes.NewReader(b))
		return list
	})
	builtinSensitivePaths = sync.OnceValue(func() []SensitivePath {
		b, _ := builtin.ReadFile("builtin/sensitive_paths.yaml")
		list, err := parseSensitivePaths(b)
		if err != nil {
			panic("config: built-in sensitive_paths.yaml: " + err.Error())
		}
		return list
	})
)

func builtinLabel(n int) string { return fmt.Sprintf("built-in (%d entries)", n) }

// BuiltinWordlistLabel is "built-in (N entries)".
func BuiltinWordlistLabel() string { return builtinLabel(len(builtinWordlist())) }

// BuiltinSensitivePathsLabel is "built-in (N entries)".
func BuiltinSensitivePathsLabel() string { return builtinLabel(len(builtinSensitivePaths())) }

// dkimSelectors are the DKIM selectors looked up for every root.
var dkimSelectors = []string{"google", "selector1", "selector2", "k1", "k2", "k3", "default", "dkim", "mail", "s1", "s2", "smtp", "mandrill", "mxvault", "everlytickey1", "everlytickey2", "zendesk1", "zendesk2", "cm", "sig1", "scph1", "mte1"}

// DKIMSelectors are the selectors the email procedure looks up.
func DKIMSelectors() []string { return slices.Clone(dkimSelectors) }

// ListHash versions jobs when list contents change.
func ListHash(list []string) string {
	sum := sha256.Sum256([]byte(strings.Join(list, "\n")))
	return hex.EncodeToString(sum[:6])
}

// DKIMSelectorHash versions email jobs. Its older format is preserved because existing
// engagement keys contain it.
func DKIMSelectorHash() string {
	sum := sha256.Sum256([]byte(strings.Join(dkimSelectors, ",")))
	return hex.EncodeToString(sum[:4])
}

// Env supplies process-style NAME=value entries. Only HOME and XDG_CONFIG_HOME are used, for
// config paths and tilde expansion. Passing values explicitly lets callers control the
// environment.
type Env []string

// Get reads the first matching environment entry, returning "" when absent.
func (e Env) Get(name string) string {
	for _, kv := range e {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

// home reads HOME from the supplied environment, returning "" when unknown.
func (e Env) home() string { return e.Get("HOME") }

// DefaultConfigPath uses $XDG_CONFIG_HOME/nyx/config.yaml or ~/.config/nyx/config.yaml. It
// returns "" without either base directory, avoiding a working-directory fallback. It bypasses
// os.UserConfigDir to keep the same location on macOS.
func DefaultConfigPath(env Env) string {
	base := env.Get("XDG_CONFIG_HOME")
	if base == "" {
		home := env.home()
		if home == "" {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "nyx", "config.yaml")
}

// setting binds a flag to its config key.
type setting struct{ flag, key string }

var settingTable = []setting{
	{"ports", "ports"}, {"risky-ports", "risky_ports"}, {"sensitive-paths", "sensitive_paths"},
	{"wordlist", "wordlist"}, {"concurrency", "concurrency"}, {"port-concurrency", "port_concurrency"}, {"rate-per-host", "rate.per_host"},
	{"rate-per-source", "rate.per_source"}, {"rate-dns", "rate.dns"}, {"crawl-depth", "crawl.max_depth"},
	{"crawl-pages", "crawl.max_pages"}, {"output-dir", "output_dir"}, {"netblock-limit", "netblock_limit"},
	{"permutations-max", "permutations.max_per_seed"}, {"archive-max-urls", "archive.max_urls"},
	{"storage-max-names", "storage.max_names"}, {"cert-expiry-days", "cert_expiry_days"},
	{"skip", "skip"}, {"certspotter-max-pages", "certspotter.max_pages"},
	{"shodan-dns-max-pages", "shodan_dns.max_pages"}, {"censys-max-pages", "censys.max_pages"}, {"chaos-max-pages", "chaos.max_pages"},
	{"permutations-max-names", "permutations.max_names"}, {"sensitive-path-max-requests", "sensitive_path_max_requests"},
	{"shodan-max-hosts", "shodan.max_hosts"}, {"reverseip-max-domains", "reverseip.max_domains"},
	{"jsparse-max-scripts", "jsparse.max_scripts"}, {"identifier-pivot-max-queries", "identifier_pivot.max_queries"},
	{"github-max-results", "github.max_results"},
	{"dnshistory-max-hosts", "dnshistory.max_hosts"}, {"origincheck-max-candidates", "origincheck.max_candidates"},
	{"eol-warn-days", "eol_warn_days"}, {"nsreverse-max-domains", "nsreverse.max_domains"},
}

// RegisterFlags exposes settings through flags while leaving credentials file-only.
func RegisterFlags(fs *pflag.FlagSet) {
	d := Defaults()
	portsRaw, riskyRaw := FormatPorts(d.Ports), FormatPorts(d.RiskyPorts)
	var pt, rt bool
	fs.Var(portsFlag{&portsRaw, &pt}, "ports", "TCP ports to check, separated by commas (e.g.: 37,53,79-81,443)")
	// Keep the long default port list out of concise flag help.
	fs.Lookup("ports").DefValue = ""
	fs.Var(portsFlag{&riskyRaw, &rt}, "risky-ports", "Ports whose being open is reported as a risk")
	fs.String("sensitive-paths", "", "YAML file of sensitive paths to request (default: "+BuiltinSensitivePathsLabel()+")")
	fs.String("wordlist", "", "Subdomain wordlist file (default: "+BuiltinWordlistLabel()+")")
	intFlag(fs, "concurrency", d.Concurrency, "Workers per procedure (ports: --port-concurrency)")
	intFlag(fs, "port-concurrency", d.PortConcurrency, "Workers for the port sweep, higher than --concurrency to prevent stalling on silent ports waiting for timeout")
	floatFlag(fs, "rate-per-host", d.Rate.PerHost, "Requests per second per dialled target IP (HTTP requests and TCP connects)")
	floatFlag(fs, "rate-per-source", d.Rate.PerSource, "Requests per second per third-party source")
	floatFlag(fs, "rate-dns", d.Rate.DNS, "DNS queries per second in total across public resolvers")
	intFlag(fs, "crawl-depth", d.Crawl.MaxDepth, "Maximum crawl depth")
	intFlag(fs, "crawl-pages", d.Crawl.MaxPages, "Maximum pages crawled per web service (0 disables the crawl)")
	intFlag(fs, "archive-max-urls", d.Archive.MaxURLs, "Maximum archived URLs recorded per root from Wayback and Common Crawl")
	intFlag(fs, "storage-max-names", d.Storage.MaxNames, "Cloud-storage bucket names guessed per root and per organisation (checked on AWS, Azure and GCP)")
	intFlag(fs, "cert-expiry-days", d.CertExpiryDays, "Report certificates that expire within this many days")
	fs.String("output-dir", d.OutputDir, "Directory in which engagement directories are created")
	fs.Bool("no-permutations", false, "Do not resolve permutations of discovered subdomain labels (default: on, including with --passive)")
	intFlag(fs, "permutations-max", d.Permutations.MaxPerSeed, "Maximum permutations generated per discovered subdomain label")
	intFlag(fs, "netblock-limit", d.NetblockLimit, "IPv4 address count above which the run stops unless --allow-large-netblocks is given")
	fs.StringArray("skip", nil, "Procedure to turn off for this run (repeatable; replaces the skip setting, and none clears it; see nyx help procedures)")
	intFlag(fs, "certspotter-max-pages", d.Certspotter.MaxPages, "Result pages followed per root from Cert Spotter")
	intFlag(fs, "shodan-dns-max-pages", d.ShodanDNS.MaxPages, "Result pages followed per root from Shodan's DNS data (one query credit each)")
	intFlag(fs, "censys-max-pages", d.Censys.MaxPages, "Result pages followed per root from Censys")
	intFlag(fs, "chaos-max-pages", d.Chaos.MaxPages, "Result pages followed per root from Chaos (it answers in one page, so this is not reached)")
	intFlag(fs, "permutations-max-names", d.Permutations.MaxNames, "Maximum permutation names generated per run; the rest are deferred to later runs")
	intFlag(fs, "sensitive-path-max-requests", d.SensitivePathMaxRequests, "Maximum sensitive-path requests sent per run; the rest are deferred to later runs")
	intFlag(fs, "shodan-max-hosts", d.Shodan.MaxHosts, "Maximum addresses looked up on Shodan per run; the rest are deferred to later runs")
	intFlag(fs, "reverseip-max-domains", d.ReverseIP.MaxDomains, "Registrable domains one address may return from reverse lookups before it is treated as shared hosting and nothing is recorded")
	intFlag(fs, "jsparse-max-scripts", d.JSParse.MaxScripts, "Maximum script files read per origin for the URLs and hostnames they name")
	intFlag(fs, "identifier-pivot-max-queries", d.IdentifierPivot.MaxQueries, "Maximum Shodan searches per run for web identifiers (tracking IDs and favicon hashes); the rest are deferred to later runs")
	intFlag(fs, "github-max-results", d.GitHub.MaxResults, "Maximum GitHub code search results read per root (at most 1000); changing it searches again")
	intFlag(fs, "dnshistory-max-hosts", d.DNSHistory.MaxHosts, "Maximum hostnames behind a CDN or WAF whose historical addresses are fetched from SecurityTrails per run; the rest are deferred to later runs")
	intFlag(fs, "origincheck-max-candidates", d.OriginCheck.MaxCandidates, "Maximum origin candidates kept, and checked, for each hostname behind a CDN or WAF")
	intFlag(fs, "eol-warn-days", d.EOLWarnDays, "Report software whose security support ends within this many days (0 turns the warning off)")
	intFlag(fs, "nsreverse-max-domains", d.NSReverse.MaxDomains, "Domains one self-hosted name server or mail host may host before it is treated as shared hosting and nothing is recorded")
}

// numberFlag preserves numeric text for combined validation in Load. Its Type avoids
// int/float64 because Viper would silently convert invalid text such as "abc" to zero.
type numberFlag struct {
	raw  string
	kind string // "integer" or "float", shown in help
}

func (n *numberFlag) String() string     { return n.raw }
func (n *numberFlag) Set(s string) error { n.raw = s; return nil }
func (n *numberFlag) Type() string       { return n.kind }

func intFlag(fs *pflag.FlagSet, name string, def int, usage string) {
	fs.Var(&numberFlag{raw: strconv.Itoa(def), kind: "integer"}, name, usage)
}

func floatFlag(fs *pflag.FlagSet, name string, def float64, usage string) {
	fs.Var(&numberFlag{raw: strconv.FormatFloat(def, 'f', -1, 64), kind: "float"}, name, usage)
}

// rawPages is the raw form of a PagedSource.
type rawPages struct {
	MaxPages string `mapstructure:"max_pages"`
}

type rawSettings struct {
	Keys            map[string]string `mapstructure:"keys"`
	Ports           []string          `mapstructure:"ports"`
	RiskyPorts      []string          `mapstructure:"risky_ports"`
	SensitivePaths  string            `mapstructure:"sensitive_paths"`
	Wordlist        string            `mapstructure:"wordlist"`
	Concurrency     string            `mapstructure:"concurrency"`
	PortConcurrency string            `mapstructure:"port_concurrency"`
	Rate            struct {
		PerHost   string `mapstructure:"per_host"`
		PerSource string `mapstructure:"per_source"`
		DNS       string `mapstructure:"dns"`
	} `mapstructure:"rate"`
	Crawl struct {
		MaxDepth string `mapstructure:"max_depth"`
		MaxPages string `mapstructure:"max_pages"`
	} `mapstructure:"crawl"`
	Archive struct {
		MaxURLs string `mapstructure:"max_urls"`
	} `mapstructure:"archive"`
	Storage struct {
		MaxNames string `mapstructure:"max_names"`
	} `mapstructure:"storage"`
	CertExpiryDays string `mapstructure:"cert_expiry_days"`
	OutputDir      string `mapstructure:"output_dir"`
	NetblockLimit  string `mapstructure:"netblock_limit"`
	Permutations   struct {
		Enabled    string `mapstructure:"enabled"`
		MaxPerSeed string `mapstructure:"max_per_seed"`
		MaxNames   string `mapstructure:"max_names"`
	} `mapstructure:"permutations"`
	Certspotter rawPages `mapstructure:"certspotter"`
	Skip        []string `mapstructure:"skip"`
	ShodanDNS   rawPages `mapstructure:"shodan_dns"`
	Censys      rawPages `mapstructure:"censys"`
	Chaos       rawPages `mapstructure:"chaos"`

	SensitivePathMaxRequests string `mapstructure:"sensitive_path_max_requests"`
	Shodan                   struct {
		MaxHosts string `mapstructure:"max_hosts"`
	} `mapstructure:"shodan"`
	ReverseIP struct {
		MaxDomains string `mapstructure:"max_domains"`
	} `mapstructure:"reverseip"`
	JSParse struct {
		MaxScripts string `mapstructure:"max_scripts"`
	} `mapstructure:"jsparse"`
	IdentifierPivot struct {
		MaxQueries string `mapstructure:"max_queries"`
	} `mapstructure:"identifier_pivot"`
	GitHub struct {
		MaxResults string `mapstructure:"max_results"`
	} `mapstructure:"github"`
	DNSHistory struct {
		MaxHosts string `mapstructure:"max_hosts"`
	} `mapstructure:"dnshistory"`
	OriginCheck struct {
		MaxCandidates string `mapstructure:"max_candidates"`
	} `mapstructure:"origincheck"`
	EOLWarnDays string `mapstructure:"eol_warn_days"`
	NSReverse   struct {
		MaxDomains string `mapstructure:"max_domains"`
	} `mapstructure:"nsreverse"`
	// KeyTests stores setup's last key-test results. Other commands accept any contents;
	// setup ignores unreadable entries.
	KeyTests any `mapstructure:"key_tests"`
}

// Load merges defaults, YAML and explicitly set flags in that order. The default config path is
// optional; explicit paths must exist. All problems are collected by setting key, including
// unreadable files and unknown keys. Returned settings retain valid values for error redaction,
// but cannot be used to run after an error.
func Load(fs *pflag.FlagSet, configPath string, env Env) (Settings, error) {
	var probs clierr.Problems
	path, data, haveFile := readConfigFile(configPath, env, &probs)
	return check(data, haveFile, path, fs, env, probs)
}

// Check validates file bytes using the same rules as Load without flags. It collects all
// problems by setting key, using "config" and path for whole-file errors. It returns valid
// settings even on error; empty data represents an empty file.
func Check(data []byte, path string, env Env) (Settings, error) {
	return check(data, true, path, nil, env, nil)
}

// check shares Load/Check validation, adding to existing file problems. haveFile identifies
// actual file data; nil fs means no flags.
func check(data []byte, haveFile bool, path string, fs *pflag.FlagSet, env Env, probs clierr.Problems) (Settings, error) {
	d := Defaults()
	v := viper.New()
	setDefaults(v, d)
	if haveFile {
		v.SetConfigType("yaml")
		if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
			probs.Add("config", path, FileReadMessage(path, err), "")
		}
	}
	bindFlags(v, fs, &probs)

	var raw rawSettings
	if err := v.UnmarshalExact(&raw); err != nil {
		probs.Add("config", path, fmt.Sprintf("config: %v", err), "")
		// Remove unknown keys and continue validating known settings.
		raw = rawSettings{}
		if err := v.Unmarshal(&raw); err != nil {
			return d, probs
		}
	}

	s := d
	s.Keys = map[string]Secret{}
	for name, val := range raw.Keys {
		s.Keys[strings.ToLower(name)] = Secret(val)
	}

	c := settingChecker{probs: &probs}
	c.ports("ports", raw.Ports, &s.Ports)
	c.ports("risky_ports", raw.RiskyPorts, &s.RiskyPorts)
	c.numbers(raw, &s)
	c.choices(raw, &s, fs)
	c.files(raw, &s, env.home())
	return s, probs.Err()
}

// setDefaults seeds Viper from typed defaults.
func setDefaults(v *viper.Viper, d Settings) {
	defaults := map[string]any{
		"ports": FormatPorts(d.Ports), "risky_ports": FormatPorts(d.RiskyPorts),
		"sensitive_paths": "", "wordlist": "", "concurrency": d.Concurrency,
		"port_concurrency": d.PortConcurrency,
		"rate.per_host":    d.Rate.PerHost, "rate.per_source": d.Rate.PerSource, "rate.dns": d.Rate.DNS,
		"crawl.max_depth": d.Crawl.MaxDepth, "crawl.max_pages": d.Crawl.MaxPages, "archive.max_urls": d.Archive.MaxURLs,
		"output_dir": d.OutputDir, "netblock_limit": d.NetblockLimit,
		"storage.max_names": d.Storage.MaxNames, "cert_expiry_days": d.CertExpiryDays,
		"permutations.enabled": d.Permutations.Enabled, "permutations.max_per_seed": d.Permutations.MaxPerSeed, "permutations.max_names": d.Permutations.MaxNames,
		"certspotter.max_pages": d.Certspotter.MaxPages, "skip": []string{},
		"shodan_dns.max_pages": d.ShodanDNS.MaxPages, "censys.max_pages": d.Censys.MaxPages, "chaos.max_pages": d.Chaos.MaxPages,
		"sensitive_path_max_requests": d.SensitivePathMaxRequests, "shodan.max_hosts": d.Shodan.MaxHosts,
		"reverseip.max_domains": d.ReverseIP.MaxDomains, "jsparse.max_scripts": d.JSParse.MaxScripts,
		"identifier_pivot.max_queries": d.IdentifierPivot.MaxQueries,
		"github.max_results":           d.GitHub.MaxResults,
		"dnshistory.max_hosts":         d.DNSHistory.MaxHosts, "origincheck.max_candidates": d.OriginCheck.MaxCandidates,
		"eol_warn_days": d.EOLWarnDays, "nsreverse.max_domains": d.NSReverse.MaxDomains,
	}
	for k, val := range defaults {
		v.SetDefault(k, val)
	}
}

// readConfigFile resolves the default or explicit path and reads its bytes. A missing default
// is allowed; an explicit file is required. Read errors add a "config" problem and clear
// haveFile.
func readConfigFile(configPath string, env Env, probs *clierr.Problems) (path string, data []byte, haveFile bool) {
	path, explicit := configPath, configPath != ""
	if !explicit {
		path = DefaultConfigPath(env)
	}
	if _, err := os.Stat(path); explicit || (path != "" && err == nil) {
		data, err := os.ReadFile(path)
		if err != nil {
			probs.Add("config", path, FileReadMessage(path, err), "")
			return path, nil, false
		}
		return path, data, true
	}
	return path, nil, false
}

// FileReadMessage shares config read/parse error wording between Load and Check.
func FileReadMessage(path string, err error) string {
	return fmt.Sprintf("config file %s: %v", path, ErrorText(err))
}

// bindFlags applies only explicitly set flags over file settings; nil skips binding.
func bindFlags(v *viper.Viper, fs *pflag.FlagSet, probs *clierr.Problems) {
	if fs == nil {
		return
	}
	for _, s := range settingTable {
		if f := fs.Lookup(s.flag); f != nil {
			if err := v.BindPFlag(s.key, f); err != nil {
				probs.Add(s.flag, "", err.Error(), "")
			}
		}
	}
}

// settingChecker parses typed settings and collects errors by key.
type settingChecker struct{ probs *clierr.Problems }

func (c settingChecker) bad(key, val, why string) {
	c.probs.Add(key, val, fmt.Sprintf("%s: invalid value %q: %s", key, val, why), "")
}

func (c settingChecker) ports(key string, items []string, dst *[]int) {
	ps, err := parsePortItems(items)
	if err != nil {
		c.bad(key, strings.Join(items, ","), err.Error())
		return
	}
	*dst = ps
}

func (c settingChecker) posInt(key, val string, min int, dst *int) {
	n, err := strconv.Atoi(strings.TrimSpace(val))
	switch {
	case err != nil:
		c.bad(key, val, "not an integer")
	case n < min:
		c.bad(key, val, fmt.Sprintf("must be at least %d", min))
	default:
		*dst = n
	}
}

func (c settingChecker) posFloat(key, val string, dst *float64) {
	f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
	switch {
	case err != nil:
		c.bad(key, val, "not a number")
	case f <= 0:
		c.bad(key, val, "must be greater than 0")
	default:
		*dst = f
	}
}

// numbers parses the numeric settings.
func (c settingChecker) numbers(raw rawSettings, s *Settings) {
	c.posInt("concurrency", raw.Concurrency, 1, &s.Concurrency)
	c.posInt("port_concurrency", raw.PortConcurrency, 1, &s.PortConcurrency)
	c.posFloat("rate.per_host", raw.Rate.PerHost, &s.Rate.PerHost)
	c.posFloat("rate.per_source", raw.Rate.PerSource, &s.Rate.PerSource)
	c.posFloat("rate.dns", raw.Rate.DNS, &s.Rate.DNS)
	c.posInt("crawl.max_depth", raw.Crawl.MaxDepth, 0, &s.Crawl.MaxDepth)
	c.posInt("crawl.max_pages", raw.Crawl.MaxPages, 0, &s.Crawl.MaxPages)
	c.posInt("archive.max_urls", raw.Archive.MaxURLs, 1, &s.Archive.MaxURLs)
	c.posInt("netblock_limit", raw.NetblockLimit, 1, &s.NetblockLimit)
	c.posInt("storage.max_names", raw.Storage.MaxNames, 1, &s.Storage.MaxNames)
	c.posInt("cert_expiry_days", raw.CertExpiryDays, 0, &s.CertExpiryDays)
	c.posInt("permutations.max_per_seed", raw.Permutations.MaxPerSeed, 1, &s.Permutations.MaxPerSeed)
	c.posInt("permutations.max_names", raw.Permutations.MaxNames, 1, &s.Permutations.MaxNames)
	c.posInt("sensitive_path_max_requests", raw.SensitivePathMaxRequests, 1, &s.SensitivePathMaxRequests)
	c.posInt("certspotter.max_pages", raw.Certspotter.MaxPages, 1, &s.Certspotter.MaxPages)
	c.posInt("shodan_dns.max_pages", raw.ShodanDNS.MaxPages, 1, &s.ShodanDNS.MaxPages)
	c.posInt("censys.max_pages", raw.Censys.MaxPages, 1, &s.Censys.MaxPages)
	c.posInt("chaos.max_pages", raw.Chaos.MaxPages, 1, &s.Chaos.MaxPages)
	c.posInt("shodan.max_hosts", raw.Shodan.MaxHosts, 1, &s.Shodan.MaxHosts)
	c.posInt("reverseip.max_domains", raw.ReverseIP.MaxDomains, 1, &s.ReverseIP.MaxDomains)
	c.posInt("jsparse.max_scripts", raw.JSParse.MaxScripts, 1, &s.JSParse.MaxScripts)
	c.posInt("identifier_pivot.max_queries", raw.IdentifierPivot.MaxQueries, 1, &s.IdentifierPivot.MaxQueries)
	c.posInt("github.max_results", raw.GitHub.MaxResults, 1, &s.GitHub.MaxResults)
	c.posInt("dnshistory.max_hosts", raw.DNSHistory.MaxHosts, 1, &s.DNSHistory.MaxHosts)
	c.posInt("origincheck.max_candidates", raw.OriginCheck.MaxCandidates, 1, &s.OriginCheck.MaxCandidates)
	c.posInt("eol_warn_days", raw.EOLWarnDays, 0, &s.EOLWarnDays)
	c.posInt("nsreverse.max_domains", raw.NSReverse.MaxDomains, 1, &s.NSReverse.MaxDomains)
	if s.GitHub.MaxResults > maxGitHubResults {
		c.bad("github.max_results", raw.GitHub.MaxResults, fmt.Sprintf("must be at most %d", maxGitHubResults))
	}
}

// choices validates skip/permutation choices, applying explicit --no-permutations.
func (c settingChecker) choices(raw rawSettings, s *Settings, fs *pflag.FlagSet) {
	if skip, err := parseSkip(raw.Skip); err != nil {
		c.bad("skip", strings.Join(raw.Skip, ","), err.Error())
	} else {
		s.Skip = skip
	}
	if enabled, err := strconv.ParseBool(strings.TrimSpace(raw.Permutations.Enabled)); err != nil {
		c.bad("permutations.enabled", raw.Permutations.Enabled, "not true or false")
	} else {
		s.Permutations.Enabled = enabled
	}
	if fs != nil {
		if f := fs.Lookup("no-permutations"); f != nil && f.Changed && f.Value.String() == "true" {
			s.Permutations.Enabled = false
		}
	}
}

// files expands path tildes and loads custom word/sensitive-path lists, falling back to
// embedded lists when unset.
func (c settingChecker) files(raw rawSettings, s *Settings, home string) {
	s.OutputDir = expandHome(raw.OutputDir, home)
	if s.OutputDir == "" {
		c.bad("output_dir", "", "must not be empty")
	}
	s.Wordlist, s.SensitivePaths = expandHome(raw.Wordlist, home), expandHome(raw.SensitivePaths, home)
	if s.Wordlist == "" {
		s.WordlistWords = slices.Clone(builtinWordlist())
	} else if b, err := os.ReadFile(s.Wordlist); err != nil {
		c.bad("wordlist", s.Wordlist, "cannot read file: "+ErrorText(err))
	} else if s.WordlistWords, err = input.ParseList(bytes.NewReader(b)); err != nil {
		c.bad("wordlist", s.Wordlist, "cannot read file: "+ErrorText(err))
	}
	if s.SensitivePaths == "" {
		s.SensitivePathEntries = slices.Clone(builtinSensitivePaths())
	} else if b, err := os.ReadFile(s.SensitivePaths); err != nil {
		c.bad("sensitive_paths", s.SensitivePaths, "cannot read file: "+ErrorText(err))
	} else if s.SensitivePathEntries, err = parseSensitivePaths(b); err != nil {
		c.bad("sensitive_paths", s.SensitivePaths, err.Error())
	}
}

// parseSkip trims, lowercases and deduplicates procedure names. A lone "none" clears the list;
// combining it with procedure names is invalid.
func parseSkip(items []string) ([]string, error) {
	out, none := SkipNames(items)
	if none && len(out) > 0 {
		return nil, fmt.Errorf("%q cannot be combined with procedure names", skipNone)
	}
	return out, nil
}

// SkipNames returns trimmed, lowercase, unique procedure names without blanks or "none". Its second
// result reports whether "none" occurred.
func SkipNames(items []string) (names []string, none bool) {
	for _, it := range items {
		it = strings.ToLower(strings.TrimSpace(it))
		switch {
		case it == "":
		case it == skipNone:
			none = true
		case !slices.Contains(names, it):
			names = append(names, it)
		}
	}
	return names, none
}

// expandHome expands only leading "~" and "~/". Config paths are not shell-expanded, so this
// avoids creating a literal "~" directory. Unknown homes and "~user" paths remain unchanged.
func expandHome(p, home string) string {
	if home == "" || (p != "~" && !strings.HasPrefix(p, "~/")) {
		return p
	}
	return filepath.Join(home, p[1:])
}

// ExpandHome applies config path expansion using env's home directory. It leaves "~user" and
// paths without a known home unchanged.
func ExpandHome(p string, env Env) string { return expandHome(p, env.home()) }

// DefaultText formats a default as YAML would store it, using built-in labels for lists and ""
// for unknown keys.
func DefaultText(key string) string {
	switch key {
	case "wordlist":
		return BuiltinWordlistLabel()
	case "sensitive_paths":
		return BuiltinSensitivePathsLabel()
	}
	return SettingText(Defaults(), key)
}

// SettingText formats a setting for storage: paths unchanged and numbers in their shortest
// form. Unknown keys return "".
func SettingText(s Settings, key string) string {
	f := func(x float64) string { return strconv.FormatFloat(x, 'f', -1, 64) }
	switch key {
	case "output_dir":
		return s.OutputDir
	case "wordlist":
		return s.Wordlist
	case "sensitive_paths":
		return s.SensitivePaths
	case "concurrency":
		return strconv.Itoa(s.Concurrency)
	case "rate.per_host":
		return f(s.Rate.PerHost)
	case "rate.per_source":
		return f(s.Rate.PerSource)
	case "rate.dns":
		return f(s.Rate.DNS)
	}
	return ""
}

// ErrorText removes operation/path prefixes so save errors do not expose temporary filenames.
func ErrorText(err error) string {
	if pe, ok := errors.AsType[*os.PathError](err); ok {
		return pe.Err.Error()
	}
	if le, ok := errors.AsType[*os.LinkError](err); ok {
		return le.Err.Error()
	}
	return err.Error()
}
