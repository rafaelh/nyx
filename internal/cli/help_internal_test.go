package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
)

// rootWith is the tree with one more command, as a later command adds itself.
func rootWith(t *testing.T) *cobra.Command {
	t.Helper()
	inv := newInvocation(withDefaults(Deps{Stages: nil}), nil)
	root := newRoot(inv)
	extra := &cobra.Command{
		Use:     "kev <id>... [flags]",
		Short:   "Look up known exploited vulnerabilities",
		Example: "  nyx kev CVE-2021-44228 --json\n  nyx kev CVE-2021-44228 CVE-2014-0160 --json",
		Annotations: map[string]string{
			annotationValues: "Fields accepted by --fields: id, score, summary",
		},
		RunE: func(*cobra.Command, []string) error { return nil },
	}
	extra.Flags().Bool("all", false, "Walk every page")
	extra.Flags().String("fields", "", "Fields to return")
	root.AddCommand(extra)
	return root
}

// A command added to the tree is in the root help, with its example, its
// flags and the values of its fixed-set flags, and the pre-scan knows it,
// with no second list of commands to keep in step.
func TestRootHelp_CommandAddedLater(t *testing.T) {
	t.Parallel()
	root := rootWith(t)
	help := rootHelp(root, layout.Stream{})
	for _, want := range []string{
		"nyx kev <id>... [flags]", "Look up known exploited vulnerabilities", "Example: nyx kev CVE-2021-44228 --json",
		"--all", "Walk every page", "--fields", "Fields accepted by --fields: id, score, summary",
		"nyx recon [domain...] [flags]",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("the root help lacks %q:\n%s", want, help)
		}
	}
	// Its first example is among the examples the help opens with.
	examples, _, _ := strings.Cut(help, "\n\n")
	if !strings.Contains(examples, "nyx kev CVE-2021-44228 --json") {
		t.Errorf("the opening examples lack the new command's:\n%s", examples)
	}
	if strings.Contains(help, "CVE-2014-0160") {
		t.Error("the root help shows more than one example of the command")
	}

	// The pre-scan knows it as a command, and its flag as no recon flag.
	if sc := classify([]string{"kev", "CVE-1"}, root); sc.err != nil || sc.help || sc.version {
		t.Errorf("kev: %+v", sc)
	}
	if sc := classify([]string{"--all", "CVE-1"}, root); sc.err == nil || sc.err.Message != "no command given" {
		t.Errorf("--all with no command: %+v", sc.err)
	}
	if sc := classify([]string{"--all", "kev", "CVE-1"}, root); sc.err == nil || sc.err.Hint != "nyx kev --all CVE-1" {
		t.Errorf("--all before kev: %+v", sc.err)
	}
	// A flag both recon and kev took is the old form of a call when the first positional has a dot,
	// as a domain does, and is ambiguous with no command otherwise.
	for _, c := range root.Commands() {
		if c.Name() == "kev" || c.Name() == "recon" {
			c.Flags().Bool("both", false, "")
		}
	}
	if sc := classify([]string{"--both", "x.com"}, root); sc.err == nil || sc.err.Hint != "nyx recon --both x.com" {
		t.Errorf("--both x.com: %+v", sc.err)
	}
	if sc := classify([]string{"--both", "CVE-1"}, root); sc.err == nil || sc.err.Message != "no command given" || sc.err.Hint != "nyx --help" {
		t.Errorf("--both CVE-1: %+v", sc.err)
	}
}

// terminalAt is a terminal stream of depth d that is cols wide.
func terminalAt(d palette.Depth, cols int) layout.Stream {
	return layout.Stream{Terminal: true, Depth: d, Width: func() int { return cols }}
}

// screens are every help screen's blocks: the root help, each command's own help and the topics.
func screens(t *testing.T) map[string][]helpBlock {
	t.Helper()
	inv := newInvocation(withDefaults(DefaultDeps()), nil)
	root := newRoot(inv)
	out := map[string][]helpBlock{
		"root":     rootHelpBlocks(root),
		"findings": findingsBlocks(),
		"stages":   stagesBlocks(inv.d.Stages),
	}
	for _, c := range runnable(root) {
		out[c.CommandPath()] = commandHelpBlocks(c)
	}
	if len(out) < 6 {
		t.Fatalf("only %d screens", len(out))
	}
	return out
}

// At 80 columns every line of every help screen is at most 80 cells wide, coloured or not, but for
// a usage or example block, which is never broken and so is held to be written as it is, but for
// an example's colour.
func TestHelp_EveryScreenFitsEighty(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		s := terminalAt(d, 80)
		for name, blocks := range screens(t) {
			for _, b := range blocks {
				got := layoutBlock(b, s)
				switch b.kind {
				case blockUsage, blockExample:
					if want := plainHelp([]helpBlock{b}); sgrStrip(got) != want {
						t.Errorf("%s: a %d block was laid out as %q, want %q", name, b.kind, got, want)
					}
					continue
				case blockHeading, blockSummary, blockFlags, blockCommands, blockValues, blockParagraph, blockTable, blockBlank:
				}
				for l := range strings.SplitSeq(strings.TrimSuffix(got, "\n"), "\n") {
					if w := layout.Measure(l); w > 80 {
						t.Errorf("%s (depth %d): a line of block kind %d is %d cells wide: %q", name, d, b.kind, w, sgrStrip(l))
					}
				}
			}
		}
	}
}

func sgrStrip(s string) string {
	for {
		i := strings.Index(s, "\x1b[")
		if i < 0 {
			return s
		}
		j := strings.IndexByte(s[i:], 'm')
		if j < 0 {
			return s
		}
		s = s[:i] + s[i+j+1:]
	}
}

// A protected word longer than the space left for it is left whole, so its line runs past the width
// and no other line does.
func TestHelp_ProtectedWordRunsPast(t *testing.T) {
	t.Parallel()
	const url = "https://example.com/a/path/that/is/much/longer/than/the/width/of/the/terminal/it/is/written/to/index.html"
	blocks := freeBlocks("The details are at "+url+" and nowhere else, so this paragraph wraps around the address.", nil)
	got := strings.Split(strings.TrimSuffix(layoutBlock(blocks[0], terminalAt(palette.None, 80)), "\n"), "\n")
	over := 0
	for _, l := range got {
		if layout.Measure(l) > 80 {
			over++
			if strings.TrimSpace(l) != url {
				t.Errorf("a line past the width holds more than the address: %q", l)
			}
		}
	}
	if over != 1 || !strings.Contains(strings.Join(got, "\n"), url) {
		t.Errorf("want one line past the width holding the whole address:\n%s", strings.Join(got, "\n"))
	}
}

// Free text is split into blocks: a blank line ends a paragraph, an unindented line that ends in a
// colon is a heading, a run of lines with one indent is a paragraph and a change of indent starts
// another, and a named line is a list of values.
func TestFreeBlocks(t *testing.T) {
	t.Parallel()
	text := "Intro line one\nintro line two\n\nSection:\n  indented one\n  indented two\n    deeper\nFields accepted by --x: a, b\n\n\nEnd"
	type blk struct {
		kind  blockKind
		lines []string
	}
	var got []blk
	for _, b := range freeBlocks(text, map[string]bool{"Fields accepted by --x: a, b": true}) {
		got = append(got, blk{b.kind, b.lines})
	}
	want := []blk{
		{blockParagraph, []string{"Intro line one", "intro line two"}},
		{blockBlank, []string{""}},
		{blockHeading, []string{"Section:"}},
		{blockParagraph, []string{"  indented one", "  indented two"}},
		{blockParagraph, []string{"    deeper"}},
		{blockValues, []string{"Fields accepted by --x: a, b"}},
		{blockBlank, []string{""}},
		{blockBlank, []string{""}},
		{blockParagraph, []string{"End"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("blocks\n got %v\nwant %v", got, want)
	}
	// Blocks written off a terminal are the lines they were made from.
	if plain := plainHelp(freeBlocks(text, nil)); plain != text+"\n" {
		t.Errorf("plain join %q, want %q", plain, text+"\n")
	}
}
