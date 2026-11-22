package iplookup

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/batch"
	"github.com/rafaelh/nyx/internal/clierr"
)

// InputResult is how one input ended before any of its addresses was looked up.
type InputResult struct {
	// Input is the input as given (trimmed).
	Input string
	// Err is why the input failed: INVALID_INPUT for one that is not an address, a CIDR or a
	// hostname, NOT_FOUND for a name with no address, NETWORK_ERROR or TIMEOUT (transient) for a
	// resolver that failed. Nil when the input gave addresses.
	Err *clierr.Error
	// Addresses are the canonical addresses the input gave, in order. Nil when Err is set.
	Addresses []string
}

// AddressResult is how one address's lookup ended.
type AddressResult struct {
	Record Record
	// Asked are the sources the lookup asked for this address: the ones the selection needs
	// (Fields.Sources) less those it did not ask because they do not apply (HackerTarget for an
	// IPv6 or a shared address) and, under --active, with probe only for an address it contacted.
	// A source that was asked and did not answer is in the record's failures. A non-public
	// address's Asked is not read: it is a success whatever failed.
	Asked []Source
	// Answered is true when a selected key that needs no source has its value (Fields.Sourceless):
	// a source that always answers, so an address whose only failed source is Team Cymru still has
	// its record.
	Answered bool
}

// verdict is how an address ended.
type verdict struct {
	failing []Failure // the failures that count: every one that is not a quota failure
	none    bool      // no source it asked answered, so it is a failed input and has no record
}

// judge decides how an address ended. A non-public address is a success, and a quota failure
// never counts: not against success, not towards the none-answered rule, and not for a retry. An
// address fails when a source it asked did not answer, and has no record when none did (quota
// aside).
func judge(r AddressResult) verdict {
	if r.Record.Kind != addrkind.Public {
		return verdict{}
	}
	var v verdict
	var quotaSources, failedSources []Source
	for _, f := range r.Record.Failures {
		if f.Quota {
			quotaSources = append(quotaSources, f.Source)
			continue
		}
		v.failing = append(v.failing, f)
		failedSources = append(failedSources, f.Source)
	}
	if len(v.failing) == 0 {
		return v
	}
	slices.SortStableFunc(v.failing, func(a, b Failure) int { return sourceRank(a.Source) - sourceRank(b.Source) })
	v.none = !r.Answered && !slices.ContainsFunc(r.Asked, func(s Source) bool {
		return !slices.Contains(quotaSources, s) && !slices.Contains(failedSources, s)
	})
	return v
}

// err is the error of a failed address: its first failing source's code, every failing source's
// message, and transient when any of them is.
func (v verdict) err() *clierr.Error {
	e := &clierr.Error{Code: v.failing[0].Code}
	msgs := make([]string, len(v.failing))
	for i, f := range v.failing {
		msgs[i] = fmt.Sprintf("%s: %s", f.Source, f.Message)
		e.Transient = e.Transient || f.Transient
	}
	e.Message = strings.Join(msgs, "; ")
	return e
}

// ErrorInput is the input of a meta.errors entry: the inputs as given that failed or that gave
// the failed address, and for an address that failed, the address.
type ErrorInput struct {
	Input   []string `json:"input"`
	Address string   `json:"address,omitempty"`
}

// Outcome is how a call ends, from how each input and each address ended, both in the order they
// were given. It returns the records to write (every address that has one, in order), a
// meta.errors entry for each failure and the error the call ends with, nil when nothing failed.
//
// A failure is an input that failed before any lookup (invalid, NOT_FOUND, a resolver failure), or
// an address that failed (see AddressResult), reported once however many inputs gave it. An
// address with a failed source still has its record, and is a failure; one for which no source
// answered has no record. The error is built by internal/batch as nyx cve's is: with no record
// and one code it has that code, else it is PARTIAL, and its hint is command run on the failing
// addresses and on the hostnames whose resolution failed, for the failures worth retrying. A
// failed address has the code of its first failing source in the record's order. Its message
// counts the addresses and inputs that failed against those looked up, so "1 of 2 inputs
// returned" may count addresses. The failures are named by address in the messages, but the
// error's input lists what the caller typed: every input that failed or that gave a failed
// address, once each, in order; each meta.errors entry names its address.
func Outcome(inputs []InputResult, addrs []AddressResult, command func(retry []string) string) ([]Record, []*clierr.Error, *clierr.Error) {
	verdicts := make(map[string]verdict, len(addrs))
	var records []Record
	for _, a := range addrs {
		v := judge(a)
		verdicts[a.Record.Address] = v
		if !v.none {
			records = append(records, a.Record)
		}
	}
	// The inputs that gave each address, in the order given.
	givenBy := map[string][]string{}
	for _, in := range inputs {
		for _, a := range in.Addresses {
			if !slices.Contains(givenBy[a], in.Input) {
				givenBy[a] = append(givenBy[a], in.Input)
			}
		}
	}
	var failures []batch.Failure
	total := len(addrs)
	reported := map[string]bool{}
	failAddress := func(a string) {
		if v := verdicts[a]; len(v.failing) > 0 && !reported[a] {
			reported[a] = true
			given := givenBy[a]
			if given == nil {
				given = []string{} // an address no input names lists none
			}
			failures = append(failures, batch.Failure{
				Name: a, Entry: ErrorInput{Input: givenBy[a], Address: a}, Given: given, Retry: a, Err: v.err(),
			})
		}
	}
	for _, in := range inputs {
		if in.Err != nil {
			total++
			failures = append(failures, batch.Failure{Name: in.Input, Entry: ErrorInput{Input: []string{in.Input}}, Retry: in.Input, Err: in.Err})
			continue
		}
		for _, a := range in.Addresses {
			failAddress(a)
		}
	}
	for _, a := range addrs { // an address no input names, which a caller should not give
		failAddress(a.Record.Address)
	}
	metaErrs, err := batch.Outcome(batch.Config{Noun: "inputs", Key: "input", Command: command},
		total, len(records), failures)
	return records, metaErrs, err
}
