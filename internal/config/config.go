// Package config loads and validates nyx settings from a YAML file,
// environment variables and flags (file < env < flag).
package config

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

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

// JSParse holds the settings of the jsparse stage.
type JSParse struct {
	// MaxScripts caps the scripts fetched per script origin. It is not part of a check's key: a
	// script already read keeps its place when new scripts appear, raising the cap fetches the
	// scripts left over, and lowering it below the number already read retires those past the cap,
	// in URL order.
	MaxScripts int
}

// Archive holds the limits on URLs taken from public archives.
type Archive struct{ MaxURLs int }

// Permutations holds the subdomain-permutation settings.
type Permutations struct {
	Enabled    bool
	MaxPerSeed int
	MaxNames   int
}

// Storage holds the cloud-storage settings.
type Storage struct {
	// MaxNames caps the bucket names guessed per root and per organisation.
	MaxNames int
}

// Shodan holds the settings of the shodan-host stage.
type Shodan struct {
	// MaxHosts caps the addresses looked up per run; the rest are deferred.
	MaxHosts int
}

// IdentifierPivot holds the settings of the identifier-pivot stage.
type IdentifierPivot struct {
	// MaxQueries caps the Shodan searches sent per run; the rest are deferred.
	MaxQueries int
}

// ReverseIP holds the settings of the reverseip stage.
type ReverseIP struct {
	// MaxDomains is the number of distinct registrable domains one address may return before it is
	// treated as shared hosting and nothing is recorded. It is part of the check, so changing it
	// asks every address again.
	MaxDomains int
}

// DNSHistory holds the settings of the dnshistory stage.
type DNSHistory struct {
	// MaxHosts caps the hostnames whose history is fetched per run; the rest are deferred.
	MaxHosts int
}

// OriginCheck holds the settings of origin exposure: how many origin candidates are kept for each
// hostname behind a CDN or WAF. It is shared by the origincheck stage and the findings, so the
// stage checks the candidates the findings report.
type OriginCheck struct {
	MaxCandidates int
}

// GitHub holds the settings of the github stage.
type GitHub struct {
	// MaxResults caps the code search results read per root (GitHub serves at most 1,000). It is
	// part of the check, so changing it searches again.
	MaxResults int
}

// maxGitHubResults is the most results GitHub's code search serves for a query.
const maxGitHubResults = 1000

// PagedSource holds the settings of a source that follows result pages.
type PagedSource struct {
	// MaxPages caps the result pages followed per root. It is part of the check, so raising it
	// repeats the checks.
	MaxPages int
}

// skipNone is the value of --skip that clears the skip setting for a run.
const skipNone = "none"

// Settings are the validated settings for a run.
type Settings struct {
	Keys                 map[string]Secret
	Ports                []int
	RiskyPorts           []int
	SensitivePaths       string // file path; empty means the built-in list
	SensitivePathEntries []SensitivePath
	Wordlist             string // file path; empty means the built-in list
	// WordlistWords is the parsed list from Wordlist (or the built-in list) and
	// WordlistHash identifies its content, so a changed list creates new checks.
	WordlistWords []string
	WordlistHash  string
	Permutations  Permutations
	Concurrency   int
	// PortConcurrency is the number of workers of the ports stage, which is
	// slow per check (a silent port costs the connect timeout) and so needs more.
	PortConcurrency int
	Rate            Rate
	Crawl           Crawl
	Archive         Archive
	Storage         Storage
	// CertExpiryDays is how many days ahead a certificate expiry is reported.
	CertExpiryDays int
	OutputDir      string
	NetblockLimit  int // IPv4 addresses
	Certspotter    PagedSource
	// Skip names the stages to turn off. It holds only stage names: "none" is
	// resolved here, and whether each name is a stage is checked by the caller.
	Skip      []string
	ShodanDNS PagedSource
	Censys    PagedSource
	Chaos     PagedSource
	// SensitivePathMaxRequests caps the sensitive-path requests sent in one run.
	SensitivePathMaxRequests int
	Shodan                   Shodan
	ReverseIP                ReverseIP
	JSParse                  JSParse
	IdentifierPivot          IdentifierPivot
	GitHub                   GitHub
	DNSHistory               DNSHistory
	OriginCheck              OriginCheck
	// EOLWarnDays is how many days before the end of a release cycle's security support the
	// approaching finding is reported; 0 turns that finding off.
	EOLWarnDays int
}

// Defaults returns the default settings. The limits and rates are reasonable starting points, not
// taken from any source's fair-use terms or from engagement norms: tune them when there is evidence
// for a better value.
func Defaults() Settings {
	return Settings{
		Keys:            map[string]Secret{},
		Ports:           DefaultPorts(),
		RiskyPorts:      append([]int(nil), defaultRisky...),
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
		Censys:          PagedSource{MaxPages: 10},
		Chaos:           PagedSource{MaxPages: 10},

		SensitivePathMaxRequests: 50000,
	}
}

// KeyValues returns the configured key values, for building a Redactor.
func (s Settings) KeyValues() []string {
	var out []string
	for _, n := range slices.Sorted(maps.Keys(s.Keys)) {
		out = append(out, s.Keys[n].Reveal())
	}
	return out
}

func builtinWordlist() []string {
	b, _ := builtin.ReadFile("builtin/wordlist.txt")
	list, _ := input.ParseList(bytes.NewReader(b))
	return list
}

// BuiltinWordlistLabel is "built-in (N entries)".
func BuiltinWordlistLabel() string {
	return fmt.Sprintf("built-in (%d entries)", len(builtinWordlist()))
}

// BuiltinSensitivePathsLabel is "built-in (N entries)".
func BuiltinSensitivePathsLabel() string {
	return fmt.Sprintf("built-in (%d entries)", len(builtinSensitivePaths()))
}

// dkimSelectors are the DKIM selectors looked up for every root.
var dkimSelectors = []string{"google", "selector1", "selector2", "k1", "k2", "k3", "default", "dkim", "mail", "s1", "s2", "smtp", "mandrill", "mxvault", "everlytickey1", "everlytickey2", "zendesk1", "zendesk2", "cm", "sig1", "scph1", "mte1"}

// DKIMSelectors are the selectors the email stage looks up.
func DKIMSelectors() []string { return slices.Clone(dkimSelectors) }

// DKIMSelectorHash identifies the selector list, so a changed list creates new email checks.
func DKIMSelectorHash() string {
	sum := sha256.Sum256([]byte(strings.Join(dkimSelectors, ",")))
	return hex.EncodeToString(sum[:4])
}

func builtinSensitivePaths() []SensitivePath {
	b, _ := builtin.ReadFile("builtin/sensitive_paths.yaml")
	list, err := parseSensitivePaths(b)
	if err != nil {
		panic("config: built-in sensitive_paths.yaml: " + err.Error())
	}
	return list
}

// DefaultConfigPath is $XDG_CONFIG_HOME/nyx/config.yaml, or ~/.config/nyx/config.yaml. It is ""
// when neither XDG_CONFIG_HOME nor the home directory is known, so a missing $HOME never resolves
// to a config file relative to the working directory. os.UserConfigDir is deliberately not used: on
// macOS it would move the file to ~/Library/Application Support.
func DefaultConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
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
	{"eol-warn-days", "eol_warn_days"},
}

// RegisterFlags adds one flag per setting to fs. There is deliberately no flag for API keys.
func RegisterFlags(fs *pflag.FlagSet) {
	d := Defaults()
	portsRaw, riskyRaw := FormatPorts(d.Ports), FormatPorts(d.RiskyPorts)
	var pt, rt bool
	fs.Var(portsFlag{&portsRaw, &pt}, "ports", "TCP ports to check, separated by commas (e.g.: 37,53,79-81,443)")
	// The default list is about 100 ports long; leave it out of --help.
	fs.Lookup("ports").DefValue = ""
	fs.Var(portsFlag{&riskyRaw, &rt}, "risky-ports", "Ports whose being open is reported as a risk")
	fs.String("sensitive-paths", "", "YAML file of sensitive paths to request (default: "+BuiltinSensitivePathsLabel()+")")
	fs.String("wordlist", "", "Subdomain wordlist file (default: "+BuiltinWordlistLabel()+")")
	fs.Int("concurrency", d.Concurrency, "Workers per stage (ports: --port-concurrency)")
	fs.Int("port-concurrency", d.PortConcurrency, "Workers for the port sweep, higher than --concurrency to prevent stalling on silent ports waiting for timeout")
	fs.Float64("rate-per-host", d.Rate.PerHost, "Requests per second per dialled target IP (HTTP requests and TCP connects)")
	fs.Float64("rate-per-source", d.Rate.PerSource, "Requests per second per third-party source")
	fs.Float64("rate-dns", d.Rate.DNS, "DNS queries per second in total across public resolvers")
	fs.Int("crawl-depth", d.Crawl.MaxDepth, "Maximum crawl depth")
	fs.Int("crawl-pages", d.Crawl.MaxPages, "Maximum pages crawled per web service (0 disables the crawl)")
	fs.Int("archive-max-urls", d.Archive.MaxURLs, "Maximum archived URLs recorded per root from Wayback and Common Crawl")
	fs.Int("storage-max-names", d.Storage.MaxNames, "Cloud-storage bucket names guessed per root and per organisation (checked on AWS, Azure and GCP)")
	fs.Int("cert-expiry-days", d.CertExpiryDays, "Report certificates that expire within this many days")
	fs.String("output-dir", d.OutputDir, "Directory in which engagement directories are created")
	fs.Bool("no-permutations", false, "Do not resolve permutations of discovered subdomain labels (default: on, including with --passive)")
	fs.Int("permutations-max", d.Permutations.MaxPerSeed, "Maximum permutations generated per discovered subdomain label")
	fs.Int("netblock-limit", d.NetblockLimit, "IPv4 address count above which the run stops unless --allow-large-netblocks is given")
	fs.StringArray("skip", nil, "Stage to turn off for this run (repeatable; replaces the skip setting, and none clears it; see nyx help stages)")
	fs.Int("certspotter-max-pages", d.Certspotter.MaxPages, "Result pages followed per root from Cert Spotter")
	fs.Int("shodan-dns-max-pages", d.ShodanDNS.MaxPages, "Result pages followed per root from Shodan's DNS data (one query credit each)")
	fs.Int("censys-max-pages", d.Censys.MaxPages, "Result pages followed per root from Censys")
	fs.Int("chaos-max-pages", d.Chaos.MaxPages, "Result pages followed per root from Chaos (it answers in one page, so this is not reached)")
	fs.Int("permutations-max-names", d.Permutations.MaxNames, "Maximum permutation names generated per run; the rest are deferred to later runs")
	fs.Int("sensitive-path-max-requests", d.SensitivePathMaxRequests, "Maximum sensitive-path requests sent per run; the rest are deferred to later runs")
	fs.Int("shodan-max-hosts", d.Shodan.MaxHosts, "Maximum addresses looked up on Shodan per run; the rest are deferred to later runs")
	fs.Int("reverseip-max-domains", d.ReverseIP.MaxDomains, "Registrable domains one address may return from reverse lookups before it is treated as shared hosting and nothing is recorded")
	fs.Int("jsparse-max-scripts", d.JSParse.MaxScripts, "Maximum script files read per origin for the URLs and hostnames they name")
	fs.Int("identifier-pivot-max-queries", d.IdentifierPivot.MaxQueries, "Maximum Shodan searches per run for web identifiers (tracking IDs and favicon hashes); the rest are deferred to later runs")
	fs.Int("github-max-results", d.GitHub.MaxResults, "Maximum GitHub code search results read per root (at most 1000); changing it searches again")
	fs.Int("dnshistory-max-hosts", d.DNSHistory.MaxHosts, "Maximum hostnames behind a CDN or WAF whose historical addresses are fetched from SecurityTrails per run; the rest are deferred to later runs")
	fs.Int("origincheck-max-candidates", d.OriginCheck.MaxCandidates, "Maximum origin candidates kept, and checked, for each hostname behind a CDN or WAF")
	fs.Int("eol-warn-days", d.EOLWarnDays, "Report software whose security support ends within this many days (0 turns the warning off)")
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
}

// Load merges defaults, the config file, NYX_* environment variables and the flags in fs that were
// set (flags win over env, env over file). configPath "" means the default location, which is
// optional; an explicit path must exist.
func Load(fs *pflag.FlagSet, configPath string) (Settings, error) {
	d := Defaults()
	v := viper.New()
	v.SetEnvPrefix("NYX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
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
		"eol_warn_days": d.EOLWarnDays,
	}
	for k, val := range defaults {
		v.SetDefault(k, val)
	}

	path, explicit := configPath, configPath != ""
	if !explicit {
		path = DefaultConfigPath()
	}
	if _, err := os.Stat(path); explicit || (path != "" && err == nil) {
		v.SetConfigFile(path)
		v.SetConfigType("yaml")
		if err := v.ReadInConfig(); err != nil {
			return Settings{}, fmt.Errorf("config file %s: %w", path, err)
		}
	}
	if fs != nil {
		for _, s := range settingTable {
			if f := fs.Lookup(s.flag); f != nil {
				if err := v.BindPFlag(s.key, f); err != nil {
					return Settings{}, err
				}
			}
		}
	}

	var raw rawSettings
	if err := v.UnmarshalExact(&raw); err != nil {
		return Settings{}, fmt.Errorf("config: %w", err)
	}

	s := d
	s.Keys = map[string]Secret{}
	for name, val := range raw.Keys {
		s.Keys[strings.ToLower(name)] = Secret(val)
	}
	for _, kv := range os.Environ() {
		name, val, _ := strings.Cut(kv, "=")
		if src, ok := strings.CutPrefix(name, "NYX_KEYS_"); ok && val != "" {
			s.Keys[strings.ToLower(src)] = Secret(val)
		}
	}

	var errs []string
	bad := func(key, val string, why string) {
		errs = append(errs, fmt.Sprintf("%s: invalid value %q: %s", key, val, why))
	}
	ports := func(key string, items []string, dst *[]int) {
		ps, err := parsePortItems(items)
		if err != nil {
			bad(key, strings.Join(items, ","), err.Error())
			return
		}
		*dst = ps
	}
	ports("ports", raw.Ports, &s.Ports)
	ports("risky_ports", raw.RiskyPorts, &s.RiskyPorts)
	posInt := func(key, val string, min int, dst *int) {
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			bad(key, val, "not an integer")
		} else if n < min {
			bad(key, val, fmt.Sprintf("must be at least %d", min))
		} else {
			*dst = n
		}
	}
	posFloat := func(key, val string, dst *float64) {
		f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		if err != nil {
			bad(key, val, "not a number")
		} else if f <= 0 {
			bad(key, val, "must be greater than 0")
		} else {
			*dst = f
		}
	}
	posInt("concurrency", raw.Concurrency, 1, &s.Concurrency)
	posInt("port_concurrency", raw.PortConcurrency, 1, &s.PortConcurrency)
	posFloat("rate.per_host", raw.Rate.PerHost, &s.Rate.PerHost)
	posFloat("rate.per_source", raw.Rate.PerSource, &s.Rate.PerSource)
	posFloat("rate.dns", raw.Rate.DNS, &s.Rate.DNS)
	posInt("crawl.max_depth", raw.Crawl.MaxDepth, 0, &s.Crawl.MaxDepth)
	posInt("crawl.max_pages", raw.Crawl.MaxPages, 0, &s.Crawl.MaxPages)
	posInt("archive.max_urls", raw.Archive.MaxURLs, 1, &s.Archive.MaxURLs)
	posInt("netblock_limit", raw.NetblockLimit, 1, &s.NetblockLimit)
	posInt("storage.max_names", raw.Storage.MaxNames, 1, &s.Storage.MaxNames)
	posInt("cert_expiry_days", raw.CertExpiryDays, 0, &s.CertExpiryDays)
	posInt("permutations.max_per_seed", raw.Permutations.MaxPerSeed, 1, &s.Permutations.MaxPerSeed)
	posInt("permutations.max_names", raw.Permutations.MaxNames, 1, &s.Permutations.MaxNames)
	posInt("sensitive_path_max_requests", raw.SensitivePathMaxRequests, 1, &s.SensitivePathMaxRequests)
	posInt("certspotter.max_pages", raw.Certspotter.MaxPages, 1, &s.Certspotter.MaxPages)
	posInt("shodan_dns.max_pages", raw.ShodanDNS.MaxPages, 1, &s.ShodanDNS.MaxPages)
	posInt("censys.max_pages", raw.Censys.MaxPages, 1, &s.Censys.MaxPages)
	posInt("chaos.max_pages", raw.Chaos.MaxPages, 1, &s.Chaos.MaxPages)
	posInt("shodan.max_hosts", raw.Shodan.MaxHosts, 1, &s.Shodan.MaxHosts)
	posInt("reverseip.max_domains", raw.ReverseIP.MaxDomains, 1, &s.ReverseIP.MaxDomains)
	posInt("jsparse.max_scripts", raw.JSParse.MaxScripts, 1, &s.JSParse.MaxScripts)
	posInt("identifier_pivot.max_queries", raw.IdentifierPivot.MaxQueries, 1, &s.IdentifierPivot.MaxQueries)
	posInt("github.max_results", raw.GitHub.MaxResults, 1, &s.GitHub.MaxResults)
	posInt("dnshistory.max_hosts", raw.DNSHistory.MaxHosts, 1, &s.DNSHistory.MaxHosts)
	posInt("origincheck.max_candidates", raw.OriginCheck.MaxCandidates, 1, &s.OriginCheck.MaxCandidates)
	posInt("eol_warn_days", raw.EOLWarnDays, 0, &s.EOLWarnDays)
	if s.GitHub.MaxResults > maxGitHubResults {
		bad("github.max_results", raw.GitHub.MaxResults, fmt.Sprintf("must be at most %d", maxGitHubResults))
	}
	if skip, err := parseSkip(raw.Skip); err != nil {
		bad("skip", strings.Join(raw.Skip, ","), err.Error())
	} else {
		s.Skip = skip
	}
	if enabled, err := strconv.ParseBool(strings.TrimSpace(raw.Permutations.Enabled)); err != nil {
		bad("permutations.enabled", raw.Permutations.Enabled, "not true or false")
	} else {
		s.Permutations.Enabled = enabled
	}
	if fs != nil {
		if f := fs.Lookup("no-permutations"); f != nil && f.Changed && f.Value.String() == "true" {
			s.Permutations.Enabled = false
		}
	}
	s.OutputDir = expandHome(raw.OutputDir)
	if s.OutputDir == "" {
		bad("output_dir", "", "must not be empty")
	}
	s.Wordlist, s.SensitivePaths = expandHome(raw.Wordlist), expandHome(raw.SensitivePaths)
	if s.Wordlist != "" {
		if f, err := os.Open(s.Wordlist); err != nil {
			bad("wordlist", s.Wordlist, "cannot read file: "+errText(err))
		} else {
			if s.WordlistWords, err = input.ParseList(f); err != nil {
				bad("wordlist", s.Wordlist, "cannot read file: "+errText(err))
			}
			f.Close()
		}
	} else {
		s.WordlistWords = builtinWordlist()
	}
	sum := sha256.Sum256([]byte(strings.Join(s.WordlistWords, "\n")))
	s.WordlistHash = hex.EncodeToString(sum[:6])
	s.SensitivePathEntries = builtinSensitivePaths()
	if s.SensitivePaths != "" {
		b, err := os.ReadFile(s.SensitivePaths)
		if err != nil {
			bad("sensitive_paths", s.SensitivePaths, "cannot read file: "+errText(err))
		} else if s.SensitivePathEntries, err = parseSensitivePaths(b); err != nil {
			bad("sensitive_paths", s.SensitivePaths, err.Error())
		}
	}
	if len(errs) > 0 {
		return Settings{}, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return s, nil
}

// parseSkip normalises the skip list: names are trimmed, lower-cased and de-duplicated, and "none"
// alone gives an empty list. "none" beside a stage name is a contradiction, not something to guess.
func parseSkip(items []string) ([]string, error) {
	var out []string
	none := false
	for _, it := range items {
		it = strings.ToLower(strings.TrimSpace(it))
		switch {
		case it == "":
		case it == skipNone:
			none = true
		case !slices.Contains(out, it):
			out = append(out, it)
		}
	}
	if none && len(out) > 0 {
		return nil, fmt.Errorf("%q cannot be combined with stage names", skipNone)
	}
	return out, nil
}

// expandHome replaces a leading "~" or "~/" with the user's home directory. Paths from the config
// file or environment are not shell-expanded, so without this "output_dir: ~/engagements" would
// create a directory named "~". "~user" forms are left as is.
func expandHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[1:])
}

func errText(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}
