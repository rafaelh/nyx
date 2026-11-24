package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/engagement"
)

// maxListedEngagements is how many existing engagements a NOT_FOUND hint names.
const maxListedEngagements = 10

// engagementNotFound reports the original -e value and lists available engagements. Recon also
// gets a hint explaining how to start one.
func engagementNotFound(outputDir, name, given string, canStart bool) *clierr.Error {
	names := engagement.List(outputDir)
	var hint string
	switch {
	case len(names) == 0:
		hint = "no engagements in " + outputDir
	default:
		listed := names[:min(len(names), maxListedEngagements)]
		hint = "engagements in " + outputDir + ": " + strings.Join(listed, ", ")
		if more := len(names) - len(listed); more > 0 {
			hint += fmt.Sprintf(" and %d more", more)
		}
	}
	if canStart {
		if len(names) == 0 {
			hint += "; give domains, --org, --asn or --cidr to start one"
		} else {
			hint += "; or give domains, --org, --asn or --cidr to start one"
		}
	}
	return &clierr.Error{Code: clierr.NotFound, Message: fmt.Sprintf("no engagement named %q in %s", name, outputDir),
		Hint: hint, Input: map[string][]string{"engagement": {given}}}
}

// foreignProblem adds the problem of a directory that is not a nyx engagement.
func foreignProblem(probs *clierr.Problems, given, dir string) {
	probs.Add("engagement", given, dir+" exists but is not a nyx engagement",
		"choose another engagement name with -e, or move "+dir+" away")
}

// probeEngagement checks a directory before opening can create it. Foreign directories become
// validation problems using the original input value. It returns whether the engagement is
// missing and skips checks when name or outputDir is already invalid.
func probeEngagement(probs *clierr.Problems, outputDir, name, given string) (absent bool, err error) {
	if name == "" || outputDir == "" {
		return false, nil
	}
	dir := filepath.Join(outputDir, name)
	state, err := engagement.Probe(dir)
	if err != nil {
		return false, err
	}
	switch state {
	case engagement.Foreign:
		foreignProblem(probs, given, dir)
	case engagement.Absent:
		return true, nil
	case engagement.Exists:
	}
	return false, nil
}

// openError translates late Open failures, such as a newly acquired lock or foreign directory,
// into CLI errors using the original input value.
func openError(err error, given string) error {
	var ne *engagement.NotEngagementError
	var locked *engagement.LockedError
	switch {
	case errors.As(err, &ne):
		var p clierr.Problems
		foreignProblem(&p, given, ne.Dir)
		return p
	case errors.As(err, &locked):
		return &clierr.Error{Code: clierr.Locked, Message: locked.Error(), Transient: true,
			Hint: "another run holds this engagement; wait for it to finish, or use another -e"}
	}
	return err
}
