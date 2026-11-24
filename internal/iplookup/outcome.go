package iplookup

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/batch"
	"github.com/rafaelh/nyx/internal/clierr"
)

// InputResult records validation/resolution before address-source lookups.
type InputResult struct {
	// Input preserves the trimmed original argument.
	Input string
	// Err identifies invalid input, an unresolved name, or a transient resolver
	// network/timeout failure. Nil means the input produced addresses.
	Err *clierr.Error
	// Addresses are the canonical addresses the input gave, in order. Nil when Err is set.
	Addresses []string
}

// AddressResult is how one address's lookup ended.
type AddressResult struct {
	Record Record
	// Asked lists applicable selected sources, adding probe only for contacted active
	// addresses. It omits inapplicable HackerTarget requests, such as IPv6 or shared
	// hosting. Failed asked sources appear in the record. Non-public addresses count as
	// successful independently of Asked.
	Asked []Source
	// Answered indicates a selected local-only field produced a value, preserving a record
	// even if every network source failed.
	Answered bool
}

// verdict is how an address ended.
type verdict struct {
	failing []Failure // the failures that count: every one that is not a quota failure
	none    bool      // without any answered source, no record can be returned
}

// judge treats non-public addresses as successful and ignores quota failures for success and
// retry decisions. Other unanswered sources fail the address; if none answered, no record is
// returned.
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

// err combines source messages using the first failed source's code, and is transient if any
// failure is.
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

// ErrorInput preserves failed original inputs and, for failed address lookups, the resolved
// address.
type ErrorInput struct {
	Input   []string `json:"input"`
	Address string   `json:"address,omitempty"`
}

// Outcome combines input and address results in order. It keeps records with partial source
// data and emits one error per failed input or distinct address. Addresses with no answered
// source have no record. Quota failures are ignored for batch status.
//
// internal/batch chooses a shared error code when no records return and all failures agree;
// otherwise it uses PARTIAL. Address errors take the first failed source in record order. Retry
// hints use retryable addresses and unresolved hostnames. Error inputs preserve the user's
// original arguments once each; meta.errors identifies individual addresses. Counts may include
// both addresses and failed inputs.
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
