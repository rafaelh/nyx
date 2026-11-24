package iplookup

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
)

// pub is a public address's record with every key answered.
func pub(a string, failures ...Failure) Record {
	r := Record{Address: a, Hostnames: []string{}, Kind: "public", PTR: []string{}}
	for _, f := range failures {
		r.AddFailure(f)
	}
	return r
}

func fail(s Source, code clierr.Code, transient bool) Failure {
	return Failure{Source: s, Code: code, Message: string(s) + " said " + strings.ToLower(string(code)), Transient: transient}
}

func quota() Failure {
	return Failure{Source: SourceHackerTarget, Code: clierr.RateLimited, Message: "quota spent", Quota: true}
}

var twoSources = []Source{SourceCymru, SourceRDAP}

func ok(a string, asked ...Source) AddressResult {
	if asked == nil {
		asked = twoSources
	}
	return AddressResult{Record: pub(a), Asked: asked}
}

func with(a string, asked []Source, failures ...Failure) AddressResult {
	return AddressResult{Record: pub(a, failures...), Asked: asked}
}

func given(input string, addrs ...string) InputResult {
	return InputResult{Input: input, Addresses: addrs}
}

func cmd(retry []string) string { return "nyx ip " + strings.Join(retry, " ") + " --json" }

func resolveFail(input string, code clierr.Code, transient bool) InputResult {
	return InputResult{Input: input, Err: &clierr.Error{Code: code, Message: "could not resolve " + input, Transient: transient,
		Hint: "check the name"}}
}

func invalidInput(input string) InputResult {
	return InputResult{Input: input, Err: &clierr.Error{Code: clierr.InvalidInput, Message: "invalid input " + input, Hint: guide}}
}

func addresses(rs []Record) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Address)
	}
	return out
}

func TestOutcome_AllSucceed(t *testing.T) {
	t.Parallel()
	recs, metaErrs, err := Outcome(
		[]InputResult{given("1.1.1.1", "1.1.1.1"), given("example.com", "2.2.2.2", "3.3.3.3")},
		[]AddressResult{ok("1.1.1.1"), ok("2.2.2.2"), ok("3.3.3.3")}, cmd)
	if err != nil || len(metaErrs) != 0 {
		t.Fatalf("err %v, meta %v", err, metaErrs)
	}
	if !slices.Equal(addresses(recs), []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}) {
		t.Errorf("records %v", addresses(recs))
	}
	if recs, errs, err := Outcome(nil, nil, cmd); recs != nil || errs != nil || err != nil {
		t.Error("an empty call has an outcome")
	}
}

// A spent quota is listed in the record and nowhere else.
func TestOutcome_QuotaFailuresNeverCount(t *testing.T) {
	t.Parallel()
	asked := []Source{SourceCymru, SourceHackerTarget}
	recs, metaErrs, err := Outcome([]InputResult{given("1.1.1.1", "1.1.1.1"), given("2.2.2.2", "2.2.2.2")},
		[]AddressResult{with("1.1.1.1", asked, quota()), with("2.2.2.2", asked, quota())}, cmd)
	if err != nil || len(metaErrs) != 0 {
		t.Fatalf("quota failures alone gave err %v, meta %v", err, metaErrs)
	}
	if len(recs) != 2 || len(recs[0].Failures) != 1 || !recs[0].Failures[0].Quota {
		t.Errorf("the record lost its quota failure: %+v", recs)
	}
	// The only source asked ran out of quota: nothing was needed that could fail.
	recs, _, err = Outcome([]InputResult{given("1.1.1.1", "1.1.1.1")},
		[]AddressResult{with("1.1.1.1", []Source{SourceHackerTarget}, quota())}, cmd)
	if err != nil || len(recs) != 1 {
		t.Errorf("only a quota source asked: %d records, err %v", len(recs), err)
	}
}

func TestOutcome_QuotaIsLeftOutOfTheErrorAndTheHint(t *testing.T) {
	t.Parallel()
	asked := []Source{SourceCymru, SourceRDAP, SourceHackerTarget}
	recs, metaErrs, err := Outcome(
		[]InputResult{given("1.1.1.1", "1.1.1.1"), given("2.2.2.2", "2.2.2.2")},
		[]AddressResult{with("1.1.1.1", asked, quota()), with("2.2.2.2", asked, fail(SourceRDAP, clierr.Timeout, true), quota())}, cmd)
	if len(recs) != 2 || len(metaErrs) != 1 || err == nil {
		t.Fatalf("records %d, meta %d, err %v", len(recs), len(metaErrs), err)
	}
	if err.Hint != "run: nyx ip 2.2.2.2 --json" {
		t.Errorf("hint %q: the address that only ran out of quota is retried", err.Hint)
	}
	if strings.Contains(metaErrs[0].Message, "quota") || metaErrs[0].Code != clierr.Timeout {
		t.Errorf("the entry mentions the quota: %+v", metaErrs[0])
	}
	if len(recs[1].Failures) != 2 {
		t.Errorf("the record must keep both failures: %+v", recs[1].Failures)
	}
}

func TestOutcome_OneFailedSourceIsPartial(t *testing.T) {
	t.Parallel()
	recs, metaErrs, err := Outcome(
		[]InputResult{given("1.1.1.1", "1.1.1.1"), given("10.0.0.0/31", "10.0.0.0", "10.0.0.1")},
		[]AddressResult{ok("1.1.1.1"), with("10.0.0.0", twoSources, fail(SourceRDAP, clierr.UpstreamError, true)), ok("10.0.0.1")},
		func(retry []string) string {
			return "nyx ip " + strings.Join(retry, " ") + " --active --fields asn,rdap_org"
		})
	if err == nil || err.Code != clierr.Partial {
		t.Fatalf("err %+v, want PARTIAL", err)
	}
	if len(recs) != 3 {
		t.Errorf("a record with a failed source is still returned: %v", addresses(recs))
	}
	if want := "run: nyx ip 10.0.0.0 --active --fields asn,rdap_org"; err.Hint != want {
		t.Errorf("hint %q, want %q", err.Hint, want)
	}
	if !err.Transient || err.Message != "3 of 3 inputs returned, 1 failed" {
		t.Errorf("message %q transient %v", err.Message, err.Transient)
	}
	if len(metaErrs) != 1 {
		t.Fatalf("meta errors %v", metaErrs)
	}
	m := metaErrs[0]
	if m.Code != clierr.UpstreamError || !m.Transient || !strings.Contains(m.Message, "rdap said upstream_error") {
		t.Errorf("entry %+v", m)
	}
	if in, _ := m.Input.(ErrorInput); !slices.Equal(in.Input, []string{"10.0.0.0/31"}) || in.Address != "10.0.0.0" {
		t.Errorf("entry input %#v, want the CIDR as given and the address", m.Input)
	}
	if in, _ := err.Input.(map[string][]string); !slices.Equal(in["input"], []string{"10.0.0.0/31"}) || len(in) != 1 {
		t.Errorf("error input %#v, want the CIDR as given", err.Input)
	}
}

// Final errors preserve original inputs while per-address error entries identify resolved
// addresses.
func TestOutcome_TheErrorListsTheInputsAsGiven(t *testing.T) {
	t.Parallel()
	_, _, err := Outcome([]InputResult{given("example.com", "93.184.216.34")},
		[]AddressResult{with("93.184.216.34", twoSources, fail(SourceCymru, clierr.Timeout, true), fail(SourceRDAP, clierr.Timeout, true))}, cmd)
	if err == nil || err.Code != clierr.Timeout {
		t.Fatalf("err %+v, want TIMEOUT", err)
	}
	if in, _ := err.Input.(map[string][]string); !slices.Equal(in["input"], []string{"example.com"}) || len(in) != 1 {
		t.Errorf("error input %#v, want the hostname as given", err.Input)
	}
	_, _, err = Outcome(
		[]InputResult{given("a.example", "1.1.1.1"), given("10.0.0.0/31", "10.0.0.0", "10.0.0.1"), resolveFail("b.example", clierr.NotFound, false)},
		[]AddressResult{with("1.1.1.1", twoSources, fail(SourceRDAP, clierr.Timeout, true)), ok("10.0.0.0"),
			with("10.0.0.1", twoSources, fail(SourceRDAP, clierr.Timeout, true))}, cmd)
	if err == nil || err.Code != clierr.Partial {
		t.Fatalf("err %+v, want PARTIAL", err)
	}
	if in, _ := err.Input.(map[string][]string); !slices.Equal(in["input"], []string{"a.example", "10.0.0.0/31", "b.example"}) {
		t.Errorf("error input %#v, want every failing input as given", err.Input)
	}
}

func TestOutcome_FirstFailingSourceGivesTheCode(t *testing.T) {
	t.Parallel()
	// Reverse failure arrival order to ensure all-source failure still chooses record-order
	// precedence.
	recs, metaErrs, err := Outcome([]InputResult{given("1.1.1.1", "1.1.1.1")},
		[]AddressResult{with("1.1.1.1", []Source{SourceCymru, SourceRDAP, SourceInternetDB},
			fail(SourceInternetDB, clierr.RateLimited, true), fail(SourceRDAP, clierr.UpstreamError, true), fail(SourceCymru, clierr.NetworkError, true))}, cmd)
	if len(recs) != 0 {
		t.Errorf("records %v, want none", addresses(recs))
	}
	if err == nil || err.Code != clierr.NetworkError || !err.Transient {
		t.Fatalf("err %+v, want NETWORK_ERROR, transient", err)
	}
	if clierr.ExitCode(err.Code) != 1 {
		t.Error("not exit 1")
	}
	if err.Hint != "run: nyx ip 1.1.1.1 --json" || !strings.HasPrefix(err.Message, "1.1.1.1: ") {
		t.Errorf("hint %q message %q", err.Hint, err.Message)
	}
	if len(metaErrs) != 1 || metaErrs[0].Code != clierr.NetworkError {
		t.Errorf("meta %+v", metaErrs)
	}
	for _, s := range []string{"cymru", "rdap", "internetdb"} {
		if !strings.Contains(metaErrs[0].Message, s) {
			t.Errorf("the entry does not mention %s: %q", s, metaErrs[0].Message)
		}
	}
	// A source that answered keeps the record.
	recs, _, err = Outcome([]InputResult{given("1.1.1.1", "1.1.1.1")},
		[]AddressResult{with("1.1.1.1", []Source{SourceCymru, SourceRDAP}, fail(SourceCymru, clierr.NetworkError, true))}, cmd)
	if len(recs) != 1 || err == nil || err.Code != clierr.Partial {
		t.Errorf("one answered: %d records, %+v", len(recs), err)
	}
}

func TestOutcome_NoNeededSourceAnsweredWhenQuotaIsAside(t *testing.T) {
	t.Parallel()
	asked := []Source{SourceCymru, SourceHackerTarget}
	recs, _, err := Outcome([]InputResult{given("1.1.1.1", "1.1.1.1")},
		[]AddressResult{with("1.1.1.1", asked, fail(SourceCymru, clierr.Timeout, true), quota())}, cmd)
	if len(recs) != 0 || err == nil || err.Code != clierr.Timeout {
		t.Errorf("quota counted as an answer: %d records, %+v", len(recs), err)
	}
}

func TestOutcome_NonPublicAddressesSucceed(t *testing.T) {
	t.Parallel()
	r := Record{Address: "10.0.0.1", Hostnames: []string{}, Kind: "private"}
	r.AddFailure(fail(SourcePTR, clierr.Timeout, true))
	recs, metaErrs, err := Outcome([]InputResult{given("10.0.0.1", "10.0.0.1")}, []AddressResult{{Record: r, Asked: []Source{SourcePTR}}}, cmd)
	if err != nil || len(recs) != 1 || len(metaErrs) != 0 {
		t.Errorf("a non-public address failed: %d records, %+v, %v", len(recs), err, metaErrs)
	}
}

func TestOutcome_NotFoundAndMixedCodes(t *testing.T) {
	t.Parallel()
	// Every input not found: exit 3.
	recs, metaErrs, err := Outcome([]InputResult{resolveFail("a.example", clierr.NotFound, false), resolveFail("b.example", clierr.NotFound, false)}, nil, cmd)
	if len(recs) != 0 || err == nil || err.Code != clierr.NotFound || clierr.ExitCode(err.Code) != 3 || len(metaErrs) != 2 {
		t.Fatalf("all not found: %d records, %+v, %d meta", len(recs), err, len(metaErrs))
	}
	if in := metaErrs[1].Input.(ErrorInput); !slices.Equal(in.Input, []string{"b.example"}) || in.Address != "" {
		t.Errorf("entry input %#v", in)
	}
	// Not found and a failed address: mixed, exit 7.
	_, _, err = Outcome([]InputResult{resolveFail("a.example", clierr.NotFound, false), given("1.1.1.1", "1.1.1.1")},
		[]AddressResult{with("1.1.1.1", twoSources, fail(SourceCymru, clierr.Timeout, true), fail(SourceRDAP, clierr.Timeout, true))}, cmd)
	if err == nil || err.Code != clierr.Partial || clierr.ExitCode(err.Code) != 7 || err.Message != "none of 2 inputs returned" {
		t.Errorf("mixed: %+v", err)
	}
	// Not found beside a record: exit 7, and nothing to retry.
	_, _, err = Outcome([]InputResult{resolveFail("a.example", clierr.NotFound, false), given("1.1.1.1", "1.1.1.1")}, []AddressResult{ok("1.1.1.1")}, cmd)
	if err == nil || err.Code != clierr.Partial || err.Transient || err.Hint != "check the inputs that failed: a.example" {
		t.Errorf("not found beside a record: %+v", err)
	}
}

func TestOutcome_InvalidInputs(t *testing.T) {
	t.Parallel()
	recs, _, err := Outcome([]InputResult{invalidInput("x y"), given("1.1.1.1", "1.1.1.1")}, []AddressResult{ok("1.1.1.1")}, cmd)
	if len(recs) != 1 || err == nil || err.Code != clierr.Partial || err.Transient {
		t.Errorf("invalid beside a record: %+v", err)
	}
	if err.Hint != "check the inputs that failed: x y" {
		t.Errorf("hint %q: an invalid input is not worth retrying", err.Hint)
	}
	recs, _, err = Outcome([]InputResult{invalidInput("x y"), invalidInput("z w")}, nil, cmd)
	if len(recs) != 0 || err == nil || err.Code != clierr.InvalidInput || clierr.ExitCode(err.Code) != 2 {
		t.Errorf("all invalid: %+v", err)
	}
}

func TestOutcome_ResolverFailuresAreRetriedWithTheAddresses(t *testing.T) {
	t.Parallel()
	recs, metaErrs, err := Outcome(
		[]InputResult{resolveFail("flaky.example", clierr.NetworkError, true), invalidInput("x y"), given("1.1.1.1", "1.1.1.1"), given("2.2.2.2", "2.2.2.2")},
		[]AddressResult{ok("1.1.1.1"), with("2.2.2.2", twoSources, fail(SourceRDAP, clierr.Timeout, true))}, cmd)
	if len(recs) != 2 || err == nil || err.Code != clierr.Partial || !err.Transient {
		t.Fatalf("%d records, %+v", len(recs), err)
	}
	if err.Hint != "run: nyx ip flaky.example 2.2.2.2 --json" {
		t.Errorf("hint %q", err.Hint)
	}
	var codes []clierr.Code
	for _, m := range metaErrs {
		codes = append(codes, m.Code)
	}
	if !slices.Equal(codes, []clierr.Code{clierr.NetworkError, clierr.InvalidInput, clierr.Timeout}) {
		t.Errorf("entries %v, want one for each failure, in the order the inputs were given", codes)
	}
}

func TestOutcome_OnlyWhatIsWorthRetryingIsRetried(t *testing.T) {
	t.Parallel()
	permanent := Failure{Source: SourceRDAP, Code: clierr.UpstreamError, Message: "bad reply", Transient: false}
	_, _, err := Outcome([]InputResult{given("1.1.1.1", "1.1.1.1"), given("2.2.2.2", "2.2.2.2"), given("3.3.3.3", "3.3.3.3")},
		[]AddressResult{with("1.1.1.1", twoSources, permanent), with("2.2.2.2", twoSources, fail(SourceCymru, clierr.Timeout, true)), ok("3.3.3.3")}, cmd)
	if err == nil || err.Hint != "run: nyx ip 2.2.2.2 --json" || !err.Transient {
		t.Errorf("%+v", err)
	}
	_, _, err = Outcome([]InputResult{given("1.1.1.1", "1.1.1.1"), given("3.3.3.3", "3.3.3.3")},
		[]AddressResult{with("1.1.1.1", twoSources, permanent), ok("3.3.3.3")}, cmd)
	if err == nil || err.Transient || err.Hint != "check the inputs that failed: 1.1.1.1" {
		t.Errorf("nothing transient: %+v", err)
	}
	// A transient failure of any source makes the address worth a retry, whatever the others are.
	_, _, err = Outcome([]InputResult{given("1.1.1.1", "1.1.1.1")},
		[]AddressResult{with("1.1.1.1", []Source{SourceCymru, SourceRDAP, SourcePTR}, permanent, fail(SourcePTR, clierr.Timeout, true))}, cmd)
	if err == nil || !err.Transient || err.Hint != "run: nyx ip 1.1.1.1 --json" {
		t.Errorf("one transient among several: %+v", err)
	}
}

func TestOutcome_AnAddressFromTwoInputsFailsOnce(t *testing.T) {
	t.Parallel()
	_, metaErrs, err := Outcome(
		[]InputResult{given("10.1.1.0/31", "10.1.1.0", "10.1.1.1"), given("a.example.com", "10.1.1.1"), given("10.1.1.1", "10.1.1.1")},
		[]AddressResult{ok("10.1.1.0"), with("10.1.1.1", twoSources, fail(SourceRDAP, clierr.Timeout, true))}, cmd)
	if err == nil || len(metaErrs) != 1 {
		t.Fatalf("%+v, %d entries", err, len(metaErrs))
	}
	in := metaErrs[0].Input.(ErrorInput)
	if !slices.Equal(in.Input, []string{"10.1.1.0/31", "a.example.com", "10.1.1.1"}) || in.Address != "10.1.1.1" {
		t.Errorf("entry input %#v, want every input that gave the address", in)
	}
	if err.Hint != "run: nyx ip 10.1.1.1 --json" {
		t.Errorf("hint %q", err.Hint)
	}
}

func TestOutcome_MoreThanTwentyFailuresPointAtMeta(t *testing.T) {
	t.Parallel()
	var inputs []InputResult
	var addrs []AddressResult
	for i := range 25 {
		a := fmt.Sprintf("198.51.100.%d", i)
		inputs = append(inputs, given(a, a))
		addrs = append(addrs, with(a, twoSources, fail(SourceRDAP, clierr.Timeout, true)))
	}
	inputs, addrs = append(inputs, given("1.1.1.1", "1.1.1.1")), append(addrs, ok("1.1.1.1"))
	recs, metaErrs, err := Outcome(inputs, addrs, cmd)
	if err == nil || len(recs) != 26 || len(metaErrs) != 25 {
		t.Fatalf("%d records, %d entries, %+v", len(recs), len(metaErrs), err)
	}
	if !strings.Contains(err.Hint, "meta.errors") || strings.Contains(err.Hint, "198.51.100.1 ") {
		t.Errorf("hint %q", err.Hint)
	}
	// Twenty are still listed.
	_, _, err = Outcome(inputs[:20], addrs[:20], cmd)
	if err == nil || !strings.HasPrefix(err.Hint, "run: nyx ip 198.51.100.0 ") {
		t.Errorf("twenty failures: %+v", err)
	}
}

func TestOutcome_RecordsKeepTheirOrder(t *testing.T) {
	t.Parallel()
	recs, _, _ := Outcome([]InputResult{given("x", "3.3.3.3", "1.1.1.1", "2.2.2.2")},
		[]AddressResult{ok("3.3.3.3"), with("1.1.1.1", twoSources, fail(SourceCymru, clierr.Timeout, true), fail(SourceRDAP, clierr.Timeout, true)), ok("2.2.2.2")}, cmd)
	if !slices.Equal(addresses(recs), []string{"3.3.3.3", "2.2.2.2"}) {
		t.Errorf("records %v: the failed address has no record", addresses(recs))
	}
}

// Local snapshot evidence keeps a partial record when Cymru is the only failed network source.
func TestOutcome_TheSnapshotAnswersWhenTeamCymruFails(t *testing.T) {
	t.Parallel()
	failed := AddressResult{Record: pub("1.1.1.1", fail(SourceCymru, clierr.Timeout, true)), Asked: []Source{SourceCymru}, Answered: true}
	recs, metaErrs, err := Outcome([]InputResult{given("1.1.1.1", "1.1.1.1")}, []AddressResult{failed}, cmd)
	if len(recs) != 1 || len(metaErrs) != 1 || err == nil || err.Code != clierr.Partial {
		t.Errorf("%d records, %+v, %+v", len(recs), metaErrs, err)
	}
	// Without it, the same failure leaves no record.
	failed.Answered = false
	if recs, _, err := Outcome([]InputResult{given("1.1.1.1", "1.1.1.1")}, []AddressResult{failed}, cmd); len(recs) != 0 || err == nil || err.Code != clierr.Timeout {
		t.Errorf("without the snapshot: %d records, %+v", len(recs), err)
	}
	// A quota failure is still no part of it.
	q := AddressResult{Record: pub("1.1.1.1", quota()), Asked: []Source{SourceHackerTarget}, Answered: true}
	if recs, _, err := Outcome([]InputResult{given("1.1.1.1", "1.1.1.1")}, []AddressResult{q}, cmd); len(recs) != 1 || err != nil {
		t.Errorf("a quota failure with the snapshot answering: %d records, %+v", len(recs), err)
	}
}
