package orgname_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/orgname"
)

func TestTokens(t *testing.T) {
	t.Parallel()
	for org, want := range map[string][]string{
		"Acme Pty Ltd":         {"acme"},
		"Acme, Inc.":           {"acme"},
		"Big-Co Holdings GmbH": {"big", "holdings"},
		"  ACME   widgets ":    {"acme", "widgets"},
		"Ltd":                  nil,
		"":                     nil,
	} {
		if got := orgname.Tokens(org); !slices.Equal(got, want) {
			t.Errorf("Tokens(%q) = %v, want %v", org, got, want)
		}
	}
}

// Organisation matching requires all meaningful input words and rejects empty inputs.
func TestMatches(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		org, name string
		want      bool
	}{
		{"Acme Pty Ltd", "ACME NETWORKS LTD", true},
		{"Acme Widgets", "ACME-NET", false},
		{"Acme Widgets", "Acme Widgets Australia", true},
		{"Acme", "Roadrunner Pty", false},
		{"Ltd", "Ltd", false},
		{"", "anything", false},
	} {
		if got := orgname.Matches(c.org, c.name); got != c.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", c.org, c.name, got, c.want)
		}
	}
}
