package cli

import (
	"testing"

	"github.com/spf13/pflag"
)

// The retry command repeats the named flags the caller set, as typed and in the order named,
// after --json; a bool flag only when true. Each argument is quoted for a shell.
func TestRetryCommand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json bool
		args []string
		want string
	}{
		{"no flags", false, nil, "nyx ip 1.1.1.1 2001:db8::1"},
		{"every flag, in the order named whatever the order given", true, []string{"--timeout", "2m", "--fields", "asn", "--active"},
			"nyx ip 1.1.1.1 2001:db8::1 --json --active --fields asn --timeout 2m"},
		{"an empty --fields is kept", false, []string{"--fields", ""}, "nyx ip 1.1.1.1 2001:db8::1 --fields ''"},
		{"a false bool is left out", false, []string{"--active=false"}, "nyx ip 1.1.1.1 2001:db8::1"},
		{"values are quoted", false, []string{"--fields", "asn, ptr", "--timeout", "1m 5s"},
			"nyx ip 1.1.1.1 2001:db8::1 --fields 'asn, ptr' --timeout '1m 5s'"},
	}
	for _, c := range cases {
		fs := pflag.NewFlagSet("ip", pflag.ContinueOnError)
		fs.Bool("active", false, "")
		fs.String("fields", "", "")
		var timeout string
		fs.Var(timeoutFlag(&timeout), "timeout", "")
		if err := fs.Parse(c.args); err != nil {
			t.Fatal(err)
		}
		if got := retryCommand("ip", c.json, fs, "active", "fields", "timeout")([]string{"1.1.1.1", "2001:db8::1"}); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	fs := pflag.NewFlagSet("ip", pflag.ContinueOnError)
	if got := retryCommand("ip", false, fs)([]string{"it's.example.com"}); got != `nyx ip 'it'\''s.example.com'` {
		t.Errorf("an argument is quoted: %s", got)
	}
}
