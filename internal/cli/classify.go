package cli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/shellquote"
)

// scan holds the pre-parser decision: usage error, help, version or normal Cobra handling.
type scan struct {
	err           *clierr.Error
	help, version bool
}

// Shared short flags work around every command: -J, -q and -h.
const sharedShorts = "Jqh"

// sharedLongs are the long flags every command takes before or after its name.
var sharedLongs = []string{"json", "quiet", "debug", "help"}

// isShared accepts standalone, valued and clustered forms of shared flags.
func isShared(a string) bool {
	if name, ok := strings.CutPrefix(a, "--"); ok {
		name, _, _ = strings.Cut(name, "=")
		return slices.Contains(sharedLongs, name)
	}
	return isSharedCluster(a)
}

func isSharedCluster(a string) bool {
	if len(a) < 2 || a[0] != '-' || a[1] == '-' {
		return false
	}
	for _, c := range a[1:] {
		if !strings.ContainsRune(sharedShorts, c) {
			return false
		}
	}
	return true
}

// isFlag reports whether a is a flag token; "-" and "--" are not.
func isFlag(a string) bool { return strings.HasPrefix(a, "-") && a != "-" && a != "--" }

// scanShared detects shared flags before "--" without parsing them, so even invalid invocations
// report errors in the requested output mode.
func scanShared(args []string) shared {
	var sh shared
	boolFlag := func(a, name string) (bool, bool) {
		if a == name {
			return true, true
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			b, err := strconv.ParseBool(v)
			return b && err == nil, true
		}
		return false, false
	}
	for _, a := range args {
		if a == "--" {
			break
		}
		if v, ok := boolFlag(a, "--json"); ok {
			sh.json = v
		} else if v, ok := boolFlag(a, "--debug"); ok {
			sh.debug = v
		} else if v, ok := boolFlag(a, "--quiet"); ok {
			sh.quiet = v
		} else if isSharedCluster(a) {
			sh.json = sh.json || strings.Contains(a, "J")
			sh.quiet = sh.quiet || strings.Contains(a, "q")
		}
	}
	return sh
}

// classify reads command names and flags from the Cobra tree before parsing. After shared
// flags, a command name goes to Cobra and no arguments means root help or version. Unknown
// words are checked for legacy syntax. Flags before a command produce a placement error;
// recon-specific flags, or shared flags with a legacy positional value, are treated as legacy
// invocations.
func classify(args []string, root *cobra.Command) scan {
	commands := visibleCommands(root)
	first, help, version := -1, false, false
	for i, a := range args {
		if a == "--version" {
			version = true
			continue
		}
		if isShared(a) {
			help = help || a == "--help" || strings.HasPrefix(a, "--help=") || isSharedCluster(a) && strings.Contains(a, "h")
			continue
		}
		first = i
		break
	}
	if first < 0 {
		return scan{help: help || !version, version: version && !help}
	}
	tok := args[first]
	if slices.Contains(commands, tok) {
		return scan{}
	}
	if !isFlag(tok) {
		if oldFormWord(tok) {
			return scan{err: oldForm(args, tok)}
		}
		return scan{err: unknownCommand(tok, root)}
	}

	cmds := descendants(root)
	owners, _ := describeFlag(tok, cmds)
	var flags []string
	positional := ""
	for i := first; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if isShared(a) || a == "--version" {
			continue
		}
		if isFlag(a) {
			flags = append(flags, a)
			if _, next := describeFlag(a, cmds); next {
				i++ // its value
			}
			continue
		}
		if slices.Contains(commands, a) {
			return scan{err: flagFirst(args, i, flags)}
		}
		positional = a
		break
	}
	switch {
	case len(owners) == 0:
		return scan{err: &clierr.Error{Code: clierr.InvalidInput, Message: "unknown flag: " + tok, Hint: "nyx --help",
			Input: map[string][]string{"flag": {tok}}}}
	case !slices.ContainsFunc(owners, func(c *cobra.Command) bool { return !underRecon(c) }),
		slices.ContainsFunc(owners, underRecon) && oldFormWord(positional):
		return scan{err: oldForm(args, tok)}
	}
	return scan{err: &clierr.Error{Code: clierr.InvalidInput, Message: "no command given", Hint: "nyx --help"}}
}

// helpWord treats a command's first positional "help" as --help, following subcommands and
// skipping flag values. It leaves "help" unchanged after "--" or another positional argument.
func helpWord(args []string, root *cobra.Command) []string {
	c := root
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if isFlag(a) {
			if _, next := describeFlag(a, []*cobra.Command{c}); next {
				i++ // its value
			}
			continue
		}
		if sub := subcommand(c, a); sub != nil {
			c = sub
			continue
		}
		if a == "help" && c != root && c.Name() != "help" {
			out := slices.Clone(args)
			out[i] = "--help"
			return out
		}
		break
	}
	return args
}

// subcommand is c's visible subcommand named name, or nil.
func subcommand(c *cobra.Command, name string) *cobra.Command {
	for _, sub := range c.Commands() {
		if !sub.Hidden && sub.Name() == name {
			return sub
		}
	}
	return nil
}

// oldFormWord recognises legacy export syntax and domain-like dotted arguments.
func oldFormWord(a string) bool { return a == "export" || strings.Contains(a, ".") }

// visibleCommands lists non-hidden root commands.
func visibleCommands(root *cobra.Command) []string {
	var names []string
	for _, c := range root.Commands() {
		if !c.Hidden {
			names = append(names, c.Name())
		}
	}
	return names
}

// descendants walks the command tree without its root.
func descendants(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			out = append(out, sub)
			walk(sub)
		}
	}
	walk(root)
	return out
}

// underRecon reports whether c is recon or one of its children.
func underRecon(c *cobra.Command) bool {
	for ; c != nil && c.HasParent(); c = c.Parent() {
		if c.Name() == "recon" && !c.Parent().HasParent() {
			return true
		}
	}
	return false
}

// describeFlag finds which commands accept a flag and whether it consumes the next argument.
// Unknown flags have no owners and consume no value.
func describeFlag(tok string, cmds []*cobra.Command) (owners []*cobra.Command, needsNext bool) {
	if long, ok := strings.CutPrefix(tok, "--"); ok {
		name, _, inline := strings.Cut(long, "=")
		for _, c := range cmds {
			if f := c.Flags().Lookup(name); f != nil {
				owners = append(owners, c)
				needsNext = needsNext || !inline && f.NoOptDefVal == ""
			}
		}
		return owners, needsNext
	}
	shorts := tok[1:]
	for i := range len(shorts) {
		ch := shorts[i : i+1]
		if strings.Contains(sharedShorts, ch) {
			continue
		}
		takesValue := false
		for _, c := range cmds {
			if f := c.Flags().ShorthandLookup(ch); f != nil {
				owners = append(owners, c)
				takesValue = takesValue || f.NoOptDefVal == ""
			}
		}
		// The first command-specific shorthand owns the cluster; value-taking flags
		// consume the remaining text or next argument.
		return owners, takesValue && i == len(shorts)-1
	}
	return nil, false
}

// oldForm reports legacy syntax and suggests the same invocation with recon inserted after nyx.
func oldForm(args []string, first string) *clierr.Error {
	return &clierr.Error{Code: clierr.InvalidInput,
		Message: "nyx now takes a command first: what nyx did on its own is the recon command",
		Hint:    "nyx recon " + shellquote.Join(args),
		Input:   map[string][]string{"argument": {first}}}
}

// unknownCommand reports an unrecognised first command word.
func unknownCommand(word string, root *cobra.Command) *clierr.Error {
	return &clierr.Error{Code: clierr.InvalidInput,
		Message: fmt.Sprintf("unknown command %q: the commands are %s", word, strings.Join(visibleCommands(root), ", ")),
		Hint:    "nyx --help",
		Input:   map[string][]string{"command": {word}}}
}

// flagFirst suggests moving the command before its flags, preserving the rest of the
// invocation.
func flagFirst(args []string, at int, flags []string) *clierr.Error {
	moved := append([]string{args[at]}, args[:at]...)
	moved = append(moved, args[at+1:]...)
	return &clierr.Error{Code: clierr.InvalidInput, Message: "flags follow the command",
		Hint: "nyx " + shellquote.Join(moved), Input: map[string][]string{"flag": flags}}
}

// invocationHint builds a shell-quoted resume command from the original arguments. It removes
// recon's --redo flag and value, then adds insert immediately after the command name.
func invocationHint(args []string, insert ...string) string {
	var out []string
	inserted := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case !inserted && a == "recon":
			out = append(out, a)
			out = append(out, insert...)
			inserted = true
			continue
		case inserted && a == "--redo":
			i++
			continue
		case inserted && strings.HasPrefix(a, "--redo="):
			continue
		}
		out = append(out, a)
	}
	return "nyx " + shellquote.Join(out)
}
