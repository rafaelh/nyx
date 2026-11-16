package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/palette"
)

// findingsTopic is the text of nyx help findings.
var findingsTopic = "Findings and their default severities (fixed in code, not configurable; the summary lists high and medium):\n" +
	findings.HelpTable()

// newTopic builds a help topic: a command with no run of its own, which the root's help lists under
// "Help topics" and which nyx help <name>, nyx <name> and nyx <name> --help print. render gives its
// text at depth, the colour of stdout at that depth.
func newTopic(name, short string, render func(palette.Depth) string, depth palette.Depth) *cobra.Command {
	cmd := &cobra.Command{Use: name, Short: short}
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		fmt.Fprint(c.OutOrStdout(), render(depth))
	})
	return cmd
}

// findingsHelp is the findings topic at depth d.
func findingsHelp(d palette.Depth) string { return colourHelp(d, findingsTopic) }

// cobra's usage template lists topics by command path with a single space after the longest;
// topicsByName lists them by name, padded as the commands are, under a shorter heading.
func topicsByName(template string) string {
	return strings.Replace(template,
		"Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}\n  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}",
		"Help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}\n  {{rpad .Name .NamePadding }} {{.Short}}", 1)
}

var (
	// helpFlag is a flag line: indent, names, an optional value type, the gap
	// and the description.
	helpFlag = regexp.MustCompile(`^(\s+)((?:-\w, )?--[\w-]+)( \w+)?(\s{2,})(.*)$`)
	// helpAside is the default or example a flag's description ends with.
	helpAside = regexp.MustCompile(` \((?:default[ :]|e\.g\.).*\)$`)
	// helpNote is a usage note anywhere in a flag's description.
	helpNote = regexp.MustCompile(`\((?:# comments allowed|repeatable)\)`)
	// helpCommand is a line of the command list: indent, name, gap, summary.
	helpCommand = regexp.MustCompile(`^(\s+)(\S+)(\s{2,})(.*)$`)
	// helpFinding is a row of the findings table: category and type, the
	// severity and its padding, then the meaning.
	helpFinding = regexp.MustCompile(`^(\s+\S+\s+\S+\s+)(high|medium|low)(\s+)(.*)$`)
	// helpListLabel is the label of a line such as "Kinds accepted by --kind: ...".
	helpListLabel = regexp.MustCompile(`^(\S[^:]* accepted by --[\w-]+:)(.*)$`)
)

// colourHelp styles help text at depth d. It only adds escape codes around parts of lines and keeps
// every column's padding, so at palette.None the text is returned as it is. Headings are bold, flag
// and command names take the info colour, value types, defaults and examples the muted chrome
// colour, and the findings table's severities are badges as in the summary.
func colourHelp(d palette.Depth, text string) string {
	if d == palette.None {
		return text
	}
	muted := func(s string) string { return d.Text(palette.Chrome, "TIMESTAMP", s) }
	name := func(s string) string { return d.Text(palette.Semantic, "info", s) }
	lines := strings.Split(text, "\n")
	section := ""
	for i, l := range lines {
		switch {
		case l == "":
			continue
		case !strings.HasPrefix(l, " ") && strings.HasSuffix(l, ":"):
			section = l
			lines[i] = d.Bold(l)
			continue
		case !strings.HasPrefix(l, " "):
			section = ""
			if m := helpListLabel.FindStringSubmatch(l); m != nil {
				lines[i] = d.Bold(m[1]) + m[2]
			}
			continue
		}
		switch {
		case strings.HasSuffix(section, "Flags:"):
			if m := helpFlag.FindStringSubmatch(l); m != nil {
				desc, aside := m[5], ""
				if loc := helpAside.FindStringIndex(desc); loc != nil {
					desc, aside = desc[:loc[0]], muted(desc[loc[0]:])
				}
				desc = helpNote.ReplaceAllStringFunc(desc, muted) + aside
				lines[i] = m[1] + name(m[2]) + muted(m[3]) + m[4] + desc
			}
		case section == "Available Commands:" || section == "Help topics:":
			if m := helpCommand.FindStringSubmatch(l); m != nil {
				lines[i] = m[1] + name(m[2]) + m[3] + m[4]
			}
		case strings.HasPrefix(section, "Findings"):
			if m := helpFinding.FindStringSubmatch(l); m != nil {
				lines[i] = m[1] + d.Value(palette.Severity, m[2]) + " " + m[4]
			}
		}
	}
	return strings.Join(lines, "\n")
}
