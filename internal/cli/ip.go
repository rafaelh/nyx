package cli

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/iplookup"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// ipOptions are the flags of nyx ip. Its text flags are kept as given, so that a bad value is
// reported with the other problems and the retry command repeats them as typed.
type ipOptions struct {
	active          bool
	fields, timeout string
}

// ipStdin is what nyx ip reads from stdin.
var ipStdin = stdinWords{none: "no inputs given: pass one or more addresses, hostnames or CIDRs", key: "input",
	plural: "inputs", perLine: "one address, hostname or CIDR per line", asArgs: "inputs"}

// Paces and timeouts of the sources nyx ip asks, applied where the base options leave them unset.
const (
	ipDNSTimeout     = 2 * time.Second
	ipConnectTimeout = 3 * time.Second
	ipBannerWait     = 2 * time.Second
	ipHTTPTimeout    = 5 * time.Second
	ipRatePerHost    = 10
)

// ipFieldLines is the line that names the keys --fields accepts, those that only --active has
// marked as such.
func ipFieldLines() string {
	return "Fields accepted by --fields: " + strings.Join(iplookup.ChoosableFieldNames(false), ", ") + ", " +
		strings.Join(iplookup.ActiveFieldNames(), ", ") +
		" (these four only with --active), all"
}

// newIPCommand builds the ip command: who runs an address, where it is, what it is called and what
// is exposed on it, for each address, hostname or CIDR given.
func newIPCommand(inv *invocation) *cobra.Command {
	o := &ipOptions{}
	fieldsLines := ipFieldLines()
	cmd := &cobra.Command{
		Use:   "ip <input>... [flags]",
		Short: "Look up IP addresses, hostnames and CIDRs",
		Long: "ip returns one record for each address: who runs it, where it is, what it is called and what is known\n" +
			"to be exposed on it. Inputs are IPv4 and IPv6 addresses, hostnames and CIDRs, at most 256 distinct\n" +
			"addresses in all; a lone - reads them from stdin, one per line. It needs no engagement and no key,\n" +
			"writes no files and by default sends nothing to the address: only third parties and DNS resolvers\n" +
			"are contacted. --active also connects to each address that is not shared infrastructure,\n" +
			"non-public ones included.",
		Example: "  nyx ip 1.1.1.1 --json\n" +
			"  nyx ip 203.0.113.0/28 198.51.100.7 example.com\n" +
			"  nyx ip - --json < addresses.txt\n" +
			"  nyx ip 192.0.2.10 --fields asn,as_name,rdap_org,ptr --json\n" +
			"  nyx ip 192.0.2.10 --active",
		Args: cobra.ArbitraryArgs,
		Annotations: map[string]string{
			annotationEveryday: "active,fields,timeout",
			annotationValues:   fieldsLines,
			annotationFooter:   fieldsLines,
		},
		RunE: func(c *cobra.Command, args []string) error {
			return inv.start(c, runIP(c.Context(), inv, c, args, o))
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.BoolVar(&o.active, "active", false, "Also connect to each address that is not shared infrastructure, non-public ones included; passing it is the confirmation")
	f.StringVar(&o.fields, "fields", "", "Return only these fields, separated by commas, plus the address, hostnames, kind and failures; "+
		"all returns every field the mode allows")
	f.Var(timeoutFlag(&o.timeout), "timeout", "Deadline for the whole call, e.g. 30s or 2m (default grows with the number of addresses)")
	f.BoolP("help", "h", false, "Help for ip")
	return cmd
}

// runIP checks every flag and input, reporting all problems in one usage error before any request
// is made, then resolves the hostnames, looks every address up and writes the records, unless a
// signal arrived while it did.
//
// The deadline counts from the start of the call. It is the one-address value while stdin is
// read, then the value for the number of inputs while the hostnames resolve, then the value for
// the number of distinct addresses; --timeout replaces all three.
func runIP(ctx context.Context, inv *invocation, cmd *cobra.Command, args []string, o *ipOptions) error {
	started := time.Now() // the deadline counts from here; not d.Clock, which tests fix
	d := inv.d
	probs := inv.problems()
	fs := cmd.Flags()

	fields, unknown, activeOnly := iplookup.Select(o.fields, o.active)
	if !fs.Changed("fields") {
		fields = iplookup.AllFields(o.active)
	}
	for _, n := range unknown {
		probs.Add("fields", n, fmt.Sprintf("unknown field %q for --fields", n), iplookup.ValidFields(o.active))
	}
	for _, n := range activeOnly {
		probs.Add("fields", n, fmt.Sprintf("field %q is only available with --active", n),
			iplookup.ValidFields(false)+"; with --active also "+strings.Join(iplookup.ActiveFieldNames(), ", "))
	}
	timeoutSet := fs.Changed("timeout")
	var timeout time.Duration
	if timeoutSet {
		timeout = parseTimeout(probs, o.timeout, "--timeout 30s")
	}
	// deadlineFor is the deadline of the call for n addresses.
	deadlineFor := func(n int) time.Time {
		if timeoutSet {
			return started.Add(timeout)
		}
		return started.Add(iplookup.Deadline(o.active, n))
	}
	phase := func(n int) (context.Context, context.CancelFunc) { return context.WithDeadline(ctx, deadlineFor(n)) }

	stdin := lookupArgs(probs, args, ipStdin)
	inputs := args
	if slices.Contains(args, "-") {
		inputs = nil // read from stdin, or a problem already
	}
	if stdin {
		if err := probs.Err(); err != nil {
			return err
		}
		sctx, cancel := phase(1)
		lines, err := readLines(sctx, d.Stdin, ipStdin)
		cancel()
		if err != nil {
			return err
		}
		inputs = lines
	}
	plan := iplookup.ParseInputs(inputs, o.active)
	n := plan.LiteralCount()
	// A call that exits 2 lists every invalid input with its other problems.
	if len(*probs) > 0 || plan.AllInvalid() || n > iplookup.MaxAddresses {
		*probs = append(*probs, plan.Problems()...)
	}
	if n > iplookup.MaxAddresses {
		*probs = append(*probs, iplookup.CapProblem(n, false))
	}
	if err := probs.Err(); err != nil {
		return err
	}

	red := config.NewRedactor()
	em, warnings := newEmitter(inv, red)
	threat := inv.loadThreat(em, warnings, func(source string) bool { return ipReadsThreatSource(fields, source) })
	cfg := ipConfig(d.Egress, fields, red, em, threat)
	if inv.sh.debug {
		cfg.Debug = report.Say(em, "debug")
	}

	rctx, cancel := phase(plan.ProvisionalCount())
	resolved, err := iplookup.Resolve(rctx, cfg, plan)
	cancel()
	if ctx.Err() != nil {
		return context.Cause(ctx) // a signal: nothing is written
	}
	if err != nil {
		return err // a cap error: a deadline is each hostname's own failure
	}
	lctx, cancel := phase(len(resolved.Addresses))
	results := iplookup.Lookup(lctx, cfg, resolved)
	cancel()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}

	retry := retryCommand("ip", inv.sh.json, fs, "active", "fields", "timeout")
	records, metaErrs, outErr := iplookup.Outcome(resolved.Inputs, results, retry)
	return endLookup(outErr, func() error { return writeIP(inv, records, metaErrs, fields, warnings, red) })
}

// ipReadsThreatSource reports whether a selected key reads the threat-data source: the abusive_
// keys read ipapi.is's lists, and the drop_ keys Spamhaus's. A source no key reads gives no warning
// and no hint.
func ipReadsThreatSource(fields iplookup.Fields, source string) bool {
	prefix := "drop_"
	if source == threatdata.Ipapi {
		prefix = "abusive_"
	}
	return slices.ContainsFunc(fields.Names(), func(n string) bool { return strings.HasPrefix(n, prefix) })
}

// ipConfig is what the lookup needs: one egress for the resolvers and the third parties, with no
// policy, since a policy would refuse source hosts that sit under an input hostname, built from
// base so that tests can redirect it. Its own timeouts and paces fill only what base leaves unset.
func ipConfig(base egress.Options, fields iplookup.Fields, red *config.Redactor, em report.Emitter, threat threatdata.Set) iplookup.Config {
	o := ipEgressOptions(base, red)
	e := egress.New(o)
	clients := e.Clients(false, iplookup.SourceHosts())
	cfg := iplookup.Config{Fields: fields, ThirdParty: clients.ThirdParty, DNS: clients.DNS, Local: e.Local(),
		ProbeOptions: o, Abusive: threat.Abusive, Drop: &threat.Drop}
	cfg.Warn = report.Say(em, "warning")
	return cfg
}

// ipEgressOptions is base with nyx ip's timeouts, rates and paces where base has none, and without keys:
// no source nyx ip asks takes one.
func ipEgressOptions(base egress.Options, red *config.Redactor) egress.Options {
	o := base
	o.Keys, o.Redactor = nil, red
	o.DNSTimeout = cmp.Or(o.DNSTimeout, ipDNSTimeout)
	o.ConnectTimeout = cmp.Or(o.ConnectTimeout, ipConnectTimeout)
	o.BannerWait = cmp.Or(o.BannerWait, ipBannerWait)
	o.HTTPTimeout = cmp.Or(o.HTTPTimeout, ipHTTPTimeout)
	if o.RatePerHost <= 0 {
		o.RatePerHost = ipRatePerHost
	}
	rates := maps.Clone(o.SourceRates)
	if rates == nil {
		rates = map[string]float64{}
	}
	for host, r := range iplookup.SourceRates() {
		if _, ok := rates[host]; !ok {
			rates[host] = r
		}
	}
	o.SourceRates = rates
	return o
}

// writeIP writes the records cut by fields: the envelope under --json, else the readable layout,
// which writes nothing when there is no record.
func writeIP(inv *invocation, records []iplookup.Record, metaErrs []*clierr.Error, fields iplookup.Fields, warnings *report.Warnings, red *config.Redactor) error {
	d := inv.d
	projected := make([]iplookup.Projected, len(records))
	for i, r := range records {
		projected[i] = fields.Project(r)
	}
	if !inv.sh.json {
		return iplookup.Render(d.Stdout, projected, inv.st.out)
	}
	return writeEnvelope(inv, projected, metaErrs, warnings, "", red)
}
