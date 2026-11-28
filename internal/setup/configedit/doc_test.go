package configedit_test

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/rafaelh/nyx/internal/setup/configedit"
)

// edit parses src, applies f and returns the encoded document.
func edit(t *testing.T, src string, f func(d *configedit.Doc)) string {
	t.Helper()
	d, err := configedit.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	f(d)
	out, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return string(out)
}

func set(t *testing.T, d *configedit.Doc, key, val string) {
	t.Helper()
	if err := d.SetString(key, val); err != nil {
		t.Fatalf("SetString(%q): %v", key, err)
	}
}

func same(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDoc_SetReplacesInPlaceAndKeepsCommentsAndOrder(t *testing.T) {
	t.Parallel()
	src := `# nyx config

output_dir: /a # where
keys:
  # the shodan key
  shodan: old # rotate me
  foo: 'x y'
concurrency: 4
`
	got := edit(t, src, func(d *configedit.Doc) {
		set(t, d, "keys.shodan", "new")
		set(t, d, "concurrency", "8")
	})
	same(t, got, `# nyx config

output_dir: /a # where
keys:
  # the shodan key
  shodan: new # rotate me
  foo: 'x y'
concurrency: "8"
`)
}

func TestDoc_SetAddsMissingEntriesAndBlocks(t *testing.T) {
	t.Parallel()
	same(t, edit(t, "concurrency: 4\n", func(d *configedit.Doc) {
		set(t, d, "keys.shodan", "k1")
		set(t, d, "keys.github", "k2")
		set(t, d, "rate.dns", "20")
	}), `concurrency: 4
keys:
  shodan: k1
  github: k2
rate:
  dns: "20"
`)
	same(t, edit(t, "", func(d *configedit.Doc) { set(t, d, "output_dir", "/x") }), "output_dir: /x\n")
	same(t, edit(t, "keys:\nrate: # empty\n", func(d *configedit.Doc) {
		set(t, d, "keys.chaos", "k")
	}), "keys:\n  chaos: k\nrate: # empty\n")
}

// A setting or block that differs only in case is found and replaced in place, leaving one entry.
func TestDoc_CaseVariantsAreFoundAndReplacedInPlace(t *testing.T) {
	t.Parallel()
	same(t, edit(t, "Concurrency: 4\nKeys:\n  Shodan: a\n  censys: b\n", func(d *configedit.Doc) {
		set(t, d, "concurrency", "9")
		set(t, d, "keys.shodan", "z")
	}), "Concurrency: \"9\"\nKeys:\n  Shodan: z\n  censys: b\n")
	d, err := configedit.Parse([]byte("Rate:\n  PER_HOST: 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if e := d.Lookup("rate.per_host"); e.Node == nil || e.Node.Value != "3" || e.Variants != nil {
		t.Errorf("Lookup = %+v", e)
	}
}

func TestDoc_TwoVariantsOfAnEntryCollapseToOneAtTheFirstsPosition(t *testing.T) {
	t.Parallel()
	d, err := configedit.Parse([]byte("keys:\n  Shodan: a\n  other: o\n  shodan: b\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := d.Lookup("keys.shodan")
	if strings.Join(got.Variants, "|") != "keys.Shodan|keys.shodan" {
		t.Errorf("Variants = %v", got.Variants)
	}
	set(t, d, "keys.shodan", "new")
	out, _ := d.Bytes()
	same(t, string(out), "keys:\n  Shodan: new\n  other: o\n")
	if e := d.Lookup("keys.shodan"); e.Variants != nil {
		t.Errorf("still ambiguous: %v", e.Variants)
	}
}

func TestDoc_TwoVariantsOfABlockAreMergedIntoTheFirst(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, src, key, want string }{
		{"keys", "Keys:\n  shodan: a\nkeys:\n  censys: b\n", "keys.shodan", "Keys:\n  shodan: new\n  censys: b\n"},
		{"keys, entry in both", "Keys:\n  shodan: a\nkeys:\n  Shodan: b\n  censys: c\n", "keys.shodan", "Keys:\n  shodan: new\n  censys: c\n"},
		{"rate", "rate:\n  dns: 1\nRate:\n  per_host: 2\n", "rate.dns", "rate:\n  dns: \"5\"\n  per_host: 2\n"},
	} {
		d, err := configedit.Parse([]byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		if v := d.Lookup(c.key).Variants; len(v) != 2 {
			t.Errorf("%s: Variants = %v, want the two blocks", c.name, v)
		}
		val := "new"
		if strings.HasPrefix(c.key, "rate") {
			val = "5"
		}
		set(t, d, c.key, val)
		out, _ := d.Bytes()
		same(t, string(out), c.want)
	}
}

func TestDoc_ClearRemovesTheEntryWithItsOwnComments(t *testing.T) {
	t.Parallel()
	src := `# header

output_dir: /a # where
# about concurrency
concurrency: 4 # four
# foot of concurrency

keys:
  shodan: a
  # about censys
  censys: b # line
`
	same(t, edit(t, src, func(d *configedit.Doc) {
		d.Clear("concurrency")
		d.Clear("keys.censys")
		d.Clear("rate.dns") // absent: nothing
	}), `# header

output_dir: /a # where
keys:
  shodan: a
`)
}

func TestDoc_ClearingTheFirstEntryKeepsTheFileHeader(t *testing.T) {
	t.Parallel()
	// A header with no blank line after it is the first entry's own head comment.
	same(t, edit(t, "# nyx settings\nconcurrency: 4\noutput_dir: /a\n", func(d *configedit.Doc) {
		d.Clear("concurrency")
	}), "# nyx settings\n\noutput_dir: /a\n")
	// With a blank line it belongs to the document already.
	same(t, edit(t, "# nyx settings\n\nconcurrency: 4\noutput_dir: /a\n", func(d *configedit.Doc) {
		d.Clear("concurrency")
	}), "# nyx settings\n\noutput_dir: /a\n")
}

func TestDoc_ClearingTheLastEntryOfABlockRemovesTheBlock(t *testing.T) {
	t.Parallel()
	same(t, edit(t, "concurrency: 4\nkeys:\n  shodan: a\nrate:\n  dns: 3\n  per_host: 2\n", func(d *configedit.Doc) {
		d.Clear("keys.shodan")
		d.Clear("rate.dns")
		d.Clear("rate.per_host")
	}), "concurrency: 4\n")
	// A header on the first block moves to the document when the block goes.
	same(t, edit(t, "# my keys\nkeys:\n  shodan: a\nconcurrency: 4\n", func(d *configedit.Doc) {
		d.Clear("keys.shodan")
	}), "# my keys\n\nconcurrency: 4\n")
}

func TestDoc_ClearingEverythingLeavesAnEmptyFileOrJustTheHeader(t *testing.T) {
	t.Parallel()
	same(t, edit(t, "concurrency: 4\n", func(d *configedit.Doc) { d.Clear("concurrency") }), "")
	same(t, edit(t, "# header\n\nconcurrency: 4\n", func(d *configedit.Doc) { d.Clear("concurrency") }), "# header\n")
}

func TestDoc_ClearRemovesAllCaseVariantsAndEmptyBlocks(t *testing.T) {
	t.Parallel()
	same(t, edit(t, "Keys:\n  Shodan: a\n  shodan: b\nkeys:\n  SHODAN: c\nx_other: 1\n", func(d *configedit.Doc) {
		d.Clear("keys.shodan")
	}), "x_other: 1\n")
}

func TestDoc_ReplacingOrClearingAnAnchoredValueKeepsItsAliasesValues(t *testing.T) {
	t.Parallel()
	src := "rate:\n  per_host: &r 5\n  per_source: *r # same\n"
	for name, f := range map[string]func(d *configedit.Doc){
		"set":   func(d *configedit.Doc) { set(t, d, "rate.per_host", "7") },
		"clear": func(d *configedit.Doc) { d.Clear("rate.per_host") },
	} {
		out := edit(t, src, f)
		if _, err := configedit.Parse([]byte(out)); err != nil {
			t.Fatalf("%s: the saved file cannot be read back: %v\n%s", name, err, out)
		}
		if !strings.Contains(out, "per_source: 5 # same\n") {
			t.Errorf("%s: the alias lost its value or comment:\n%s", name, out)
		}
	}
}

func TestDoc_SetListWritesABlockSequenceAndKeepsItemComments(t *testing.T) {
	t.Parallel()
	same(t, edit(t, "skip: DNS,ports # why\nconcurrency: 4\n", func(d *configedit.Doc) {
		if err := d.SetList("skip", []string{"dns", "ports", "email"}); err != nil {
			t.Fatal(err)
		}
	}), "skip: # why\n  - dns\n  - ports\n  - email\nconcurrency: 4\n")
	same(t, edit(t, "skip:\n  - dns # keep\n  - Foo\n  - ports\n", func(d *configedit.Doc) {
		if err := d.SetList("skip", []string{"dns", "ports"}); err != nil {
			t.Fatal(err)
		}
	}), "skip:\n  - dns # keep\n  - ports\n")
	same(t, edit(t, "x: 1\n", func(d *configedit.Doc) {
		if err := d.SetList("skip", []string{"0123", "yes"}); err != nil {
			t.Fatal(err)
		}
	}), "x: 1\nskip:\n  - \"0123\"\n  - yes\n")
	// An empty list removes the setting.
	same(t, edit(t, "skip: [dns]\nx: 1\n", func(d *configedit.Doc) {
		if err := d.SetList("skip", nil); err != nil {
			t.Fatal(err)
		}
	}), "x: 1\n")
}

// Editing preserves unknown-source credentials and unrelated settings.
func TestDoc_UnknownEntriesSurviveByteForByte(t *testing.T) {
	t.Parallel()
	src := "keys:\n  foo: \"quoted: value # not a comment\" # mine\n  bar: 'it''s'\n  shodan: a\nzzz: [1, 2]\n"
	got := edit(t, src, func(d *configedit.Doc) { set(t, d, "keys.shodan", "b") })
	for _, line := range []string{"  foo: \"quoted: value # not a comment\" # mine\n", "  bar: 'it''s'\n", "zzz: [1, 2]\n"} {
		if !strings.Contains(got, line) {
			t.Errorf("lost %q in:\n%s", line, got)
		}
	}
}

func TestDoc_Parse(t *testing.T) {
	t.Parallel()
	for _, src := range []string{"", "\n\n", "# only a comment\n"} {
		d, err := configedit.Parse([]byte(src))
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if e := d.Lookup("keys.shodan"); e.Node != nil {
			t.Errorf("Lookup in %q = %+v", src, e)
		}
	}
	// A file that holds only comments keeps them when it is edited.
	same(t, edit(t, "# only a comment\n", func(d *configedit.Doc) { set(t, d, "concurrency", "3") }), "# only a comment\n\nconcurrency: \"3\"\n")
	for name, src := range map[string]string{
		"two documents": "a: 1\n---\nb: 2\n", "a list": "- a\n- b\n", "unclosed": "keys: [a\n", "a scalar": "just text\n",
	} {
		if _, err := configedit.Parse([]byte(src)); err == nil {
			t.Errorf("%s: Parse accepted it", name)
		}
	}
}

func TestDoc_InvalidUTF8IsRefused(t *testing.T) {
	t.Parallel()
	d, _ := configedit.Parse(nil)
	if err := d.SetString("keys.shodan", "ab\xffcd"); err == nil || strings.Contains(err.Error(), "ab") {
		t.Errorf("SetString = %v", err)
	}
	if err := d.SetList("skip", []string{"a\xff"}); err == nil {
		t.Error("SetList accepted invalid UTF-8")
	}
	if out, _ := d.Bytes(); len(out) != 0 {
		t.Errorf("the document changed: %q", out)
	}
}

// A block that is not a mapping cannot hold an entry.
func TestDoc_SetUnderANonMappingFails(t *testing.T) {
	t.Parallel()
	d, _ := configedit.Parse([]byte("keys: abc\n"))
	if err := d.SetString("keys.shodan", "x"); err == nil || strings.Contains(err.Error(), "abc") {
		t.Errorf("SetString = %v", err)
	}
}

// Every value written reads back as exactly the string given.
func TestDoc_AwkwardValuesReadBackExactly(t *testing.T) {
	t.Parallel()
	values := []string{
		"a: b", "a #b", "# x", "'q'", `"dq"`, "it's", `a"b`, "- dash", "-", "yes", "No", "true", "null", "~", "0123", "0x10", "1e3", "1_000",
		"12", "3.5", "0o17", ".inf", "héllo 日本語 🔑", "tab\there", " lead", "trail ", "multi\nline", "back\\slash", "{x}", "[x]", "&a", "*a", "!t", "%x", "@x", "`x",
		"a,b", "", strings.Repeat("long value ", 30), "ctl\x01x", " sep",
	}
	d, _ := configedit.Parse(nil)
	for i, v := range values {
		set(t, d, "keys.k"+string(rune('a'+i%26))+strings.Repeat("x", i/26), v)
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Keys map[string]string `yaml:"keys"`
	}
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for i, v := range values {
		k := "k" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		if back.Keys[k] != v {
			t.Errorf("%q read back as %q", v, back.Keys[k])
		}
	}
	// And as a node: the text DecodedText gives is the string, whatever the style.
	var n yaml.Node
	if err := yaml.Unmarshal(out, &n); err != nil {
		t.Fatal(err)
	}
}

func TestDecodedText(t *testing.T) {
	t.Parallel()
	for src, want := range map[string]string{
		"0x10": "16", "010": "8", "1_000": "1000", "5.0": "5", "0.50": "0.5", "1e2": "100", "true": "1", "false": "0",
		"abc": "abc", "'0123'": "0123", "\"a b\"": "a b", "~": "", "": "", "yes": "yes",
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte("k: "+src+"\n"), &n); err != nil {
			t.Fatal(err)
		}
		got, ok := configedit.DecodedText(n.Content[0].Content[1])
		if !ok || got != want {
			t.Errorf("DecodedText(%q) = %q, %v; want %q", src, got, ok, want)
		}
	}
	var n yaml.Node
	_ = yaml.Unmarshal([]byte("k: [a]\n"), &n)
	if _, ok := configedit.DecodedText(n.Content[0].Content[1]); ok {
		t.Error("a sequence has no text")
	}
}

// The sample config in docs/configuration.md, edited: nothing but the edited values changes.
func TestDoc_TheDocsSampleConfig(t *testing.T) {
	t.Parallel()
	const sample = `output_dir: ~/engagements
concurrency: 10
keys:
  securitytrails: your-securitytrails-key
  shodan: your-shodan-key
  virustotal: your-virustotal-key
  whoisxml: your-whoisxml-key
`
	same(t, edit(t, sample, func(d *configedit.Doc) {}), sample)
	same(t, edit(t, sample, func(d *configedit.Doc) {
		set(t, d, "keys.shodan", "rotated")
		d.Clear("keys.whoisxml")
		set(t, d, "keys.nvd", "n")
	}), `output_dir: ~/engagements
concurrency: 10
keys:
  securitytrails: your-securitytrails-key
  shodan: rotated
  virustotal: your-virustotal-key
  nvd: n
`)
}
