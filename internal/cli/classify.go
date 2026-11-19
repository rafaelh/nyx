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

// scan is what the pre-scan of the arguments decided: a usage error, the root
// help, the version, or none of them (hand the arguments to cobra).
type scan struct {
	err           *clierr.Error
	help, version bool
}

// sharedShorts are the shorthands every command takes before or after its
// name: -J (--json), -q (--quiet) and -h (--help).
const sharedShorts = "Jqh"

// sharedLongs are the long flags every command takes before or after its name.
var sharedLongs = []string{"json", "quiet", "debug", "help"}

// isShared reports whether a is one of the shared flags, alone, with a value,
// or as a cluster of shared shorthands.
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

// scanShared finds the shared flags in the arguments before a bare --,
// without parsing them, so the error is in the mode asked for even when the
// arguments do not parse.
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

// classify decides what a call is before cobra sees it, reading the command
// names and the flag sets from the tree. Shared flags are skipped, and the
// first other argument decides: a command name goes to cobra; nothing at all
// is the root help (or the version, when only that was asked for); a word
// that is no command is the old form of a call (export, or a word with a dot)
// or an unknown command; a flag is "flags follow the command" when a command
// name comes after it, else the old form of a call when only recon or its
// children take it, or when recon and another command take it and the first
// positional argument is an old-form word too.
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

// oldFormWord reports whether a positional argument marks the old form of a
// call: export, or a word with a dot.
func oldFormWord(a string) bool { return a == "export" || strings.Contains(a, ".") }

// visibleCommands are the names of the root's commands that are not hidden.
func visibleCommands(root *cobra.Command) []string {
	var names []string
	for _, c := range root.Commands() {
		if !c.Hidden {
			names = append(names, c.Name())
		}
	}
	return names
}

// descendants are every command of the tree but the root.
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

// describeFlag finds the commands that take a flag token, and whether the
// argument after it is its value. A token no command takes has no owners and
// is taken to have no value.
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
	for i := 0; i < len(shorts); i++ {
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
		// The first shorthand that is not shared decides; one that takes a
		// value takes the rest of the cluster, or the next argument.
		return owners, takesValue && i == len(shorts)-1
	}
	return nil, false
}

// oldForm is the error of a call in the form nyx took before it had commands:
// its hint is the same call with recon after nyx.
func oldForm(args []string, first string) *clierr.Error {
	return &clierr.Error{Code: clierr.InvalidInput,
		Message: "nyx now takes a command first: what nyx did on its own is the recon command",
		Hint:    "nyx recon " + shellquote.Join(args),
		Input:   map[string][]string{"argument": {first}}}
}

// unknownCommand is the error of a first word that is no command.
func unknownCommand(word string, root *cobra.Command) *clierr.Error {
	return &clierr.Error{Code: clierr.InvalidInput,
		Message: fmt.Sprintf("unknown command %q: the commands are %s", word, strings.Join(visibleCommands(root), ", ")),
		Hint:    "nyx --help",
		Input:   map[string][]string{"command": {word}}}
}

// flagFirst is the error of flags placed before the command at args[at]: its
// hint is the same call with the command moved to directly after nyx.
func flagFirst(args []string, at int, flags []string) *clierr.Error {
	moved := append([]string{args[at]}, args[:at]...)
	moved = append(moved, args[at+1:]...)
	return &clierr.Error{Code: clierr.InvalidInput, Message: "flags follow the command",
		Hint: "nyx " + shellquote.Join(moved), Input: map[string][]string{"flag": flags}}
}

// invocationHint is the caller's own call, shell-quoted, with --redo (and its value) left out after
// the recon command and every other argument kept, and with insert directly after the command. It
// is the call that carries on where a run stopped, without repeating a stage.
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
