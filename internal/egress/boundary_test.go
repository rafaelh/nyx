package egress_test

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Enforce network imports only in egress, narrowly allow unix signals/locks elsewhere and
// prohibit first-party os/exec imports.
func TestPassiveBoundaryImports(t *testing.T) {
	t.Parallel()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("go.mod not found")
		}
		root = parent
	}
	// Check each supported build target so platform-specific files cannot evade the import
	// boundary. Keep targets aligned with Makefile.
	for _, target := range []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"} {
		t.Run(strings.ReplaceAll(target, "/", "-"), func(t *testing.T) {
			t.Parallel()
			goos, goarch, _ := strings.Cut(target, "/")
			checkBoundary(t, root, goos, goarch)
		})
	}
}

// unixAllowed limits non-egress use to signals and file locks, excluding raw socket APIs.
const unixPkg = "golang.org/x/sys/unix"

var unixAllowed = map[string]map[string]bool{
	"/internal/cli":        {"SIGTERM": true, "SIGHUP": true},
	"/internal/engagement": {"Flock": true, "LOCK_EX": true, "LOCK_NB": true, "EWOULDBLOCK": true},
	"/internal/threatdata": {"Flock": true, "LOCK_EX": true, "LOCK_NB": true, "EWOULDBLOCK": true},
}

func checkBoundary(t *testing.T, root, goos, goarch string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-json=ImportPath,Dir,GoFiles,Imports", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list: %v\n%s", err, errb.String())
	}
	forbidden := map[string]bool{
		"net": true, "net/http": true, "crypto/tls": true, "syscall": true,
		"github.com/miekg/dns": true,
	}
	dec := json.NewDecoder(&out)
	checked := 0
	for dec.More() {
		var p struct {
			ImportPath string   `json:"ImportPath"`
			Dir        string   `json:"Dir"`
			GoFiles    []string `json:"GoFiles"`
			Imports    []string `json:"Imports"`
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(p.ImportPath, "/internal/") && !strings.Contains(p.ImportPath, "/cmd/") {
			continue
		}
		checked++
		inEgress := strings.HasSuffix(p.ImportPath, "/internal/egress") || strings.Contains(p.ImportPath, "/internal/egress/")
		for _, imp := range p.Imports {
			switch {
			case imp == "os/exec": // forbidden even in internal/egress
				t.Errorf("%s imports %s; nyx runs no external programs", p.ImportPath, imp)
			case inEgress:
			case forbidden[imp]:
				t.Errorf("%s imports %s directly; route it through internal/egress", p.ImportPath, imp)
			case imp == unixPkg:
				checkUnixUse(t, p.ImportPath, p.Dir, p.GoFiles)
			}
		}
	}
	if checked < 5 {
		t.Errorf("boundary test only saw %d packages", checked)
	}
}

// checkUnixUse fails for any golang.org/x/sys/unix identifier the package is
// not allowed, including a dot or blank import that would hide its uses.
func checkUnixUse(t *testing.T, importPath, dir string, files []string) {
	t.Helper()
	var allowed map[string]bool
	for suffix, names := range unixAllowed {
		if strings.HasSuffix(importPath, suffix) {
			allowed = names
		}
	}
	if allowed == nil {
		t.Errorf("%s imports golang.org/x/sys/unix; route network access through internal/egress", importPath)
		return
	}
	fset := token.NewFileSet()
	for _, name := range files {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		local := ""
		for _, spec := range f.Imports {
			if path, _ := strconv.Unquote(spec.Path.Value); path != unixPkg {
				continue
			}
			local = "unix"
			if spec.Name != nil {
				local = spec.Name.Name
			}
		}
		switch local {
		case "":
			continue
		case ".", "_":
			t.Errorf("%s: %s imports golang.org/x/sys/unix as %q", importPath, name, local)
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && !allowed[sel.Sel.Name] {
				t.Errorf("%s: %s uses unix.%s; only %v are allowed outside internal/egress",
					importPath, fset.Position(sel.Pos()), sel.Sel.Name, slices.Sorted(maps.Keys(allowed)))
			}
			return true
		})
	}
}
