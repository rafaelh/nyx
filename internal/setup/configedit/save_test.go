package configedit_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/setup/configedit"
)

// TestMain lets the test binary re-execute itself ("save-child <path> <data>") to call Save and be
// killed at a fault point.
func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == "save-child" {
		err := configedit.Save(os.Args[2], []byte(os.Args[3]), configedit.SaveOptions{NoFsync: true})
		if err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestSave_CreatesTheFileAndItsDirectoriesPrivately(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "a", "b", "config.yaml")
	if err := configedit.Save(path, []byte("concurrency: 3\n"), configedit.SaveOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, path); got != "concurrency: 3\n" {
		t.Errorf("content = %q", got)
	}
	if m := mode(t, path); m != 0o600 {
		t.Errorf("file mode = %o, want 600", m)
	}
	for _, d := range []string{"a", "a/b"} {
		if m := mode(t, filepath.Join(root, d)); m != 0o700 {
			t.Errorf("%s mode = %o, want 700", d, m)
		}
	}
	if got := names(t, filepath.Dir(path)); !slices.Equal(got, []string{"config.yaml"}) {
		t.Errorf("directory holds %v", got)
	}
}

func TestSave_TightensAnExistingFilesPermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := configedit.Save(path, []byte("new\n"), configedit.SaveOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, m := read(t, path), mode(t, path); got != "new\n" || m != 0o600 {
		t.Errorf("content %q, mode %o", got, m)
	}
}

// layout returns symlink path, target file and expected preserved link text.
type layout func(t *testing.T, root string) (path, target, linkTo string)

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func link(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Fatal(err)
	}
}

// saveThroughLink checks target replacement, link preservation and temporary-file cleanup.
func saveThroughLink(t *testing.T, l layout, targetExists bool) {
	t.Helper()
	root := t.TempDir()
	path, target, linkTo := l(t, root)
	if targetExists {
		if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := configedit.Save(path, []byte("new\n"), configedit.SaveOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(path); err != nil || got != linkTo {
		t.Errorf("the link is now %q (%v), want it to stay %q", got, err, linkTo)
	}
	if got := read(t, target); got != "new\n" {
		t.Errorf("target = %q", got)
	}
	if m := mode(t, target); m != 0o600 {
		t.Errorf("target mode = %o", m)
	}
	if got := names(t, filepath.Dir(target)); !slices.Equal(got, []string{"config.yaml"}) {
		t.Errorf("target directory holds %v", got)
	}
}

// A symlink at the config path is followed: the file it points to is updated and the link stays.
func TestSave_FollowsAnAbsoluteSymlink(t *testing.T) {
	t.Parallel()
	saveThroughLink(t, func(t *testing.T, root string) (string, string, string) {
		mkdirs(t, filepath.Join(root, "real"))
		target := filepath.Join(root, "real", "config.yaml")
		link(t, target, filepath.Join(root, "link.yaml"))
		return filepath.Join(root, "link.yaml"), target, target
	}, true)
}

func TestSave_FollowsARelativeSymlinkFromItsOwnDirectory(t *testing.T) {
	t.Parallel()
	saveThroughLink(t, func(t *testing.T, root string) (string, string, string) {
		mkdirs(t, filepath.Join(root, "real"), filepath.Join(root, "etc"))
		linkTo := filepath.Join("..", "real", "config.yaml")
		link(t, linkTo, filepath.Join(root, "etc", "link.yaml"))
		return filepath.Join(root, "etc", "link.yaml"), filepath.Join(root, "real", "config.yaml"), linkTo
	}, true)
}

func TestSave_ADanglingSymlinkCreatesItsTarget(t *testing.T) {
	t.Parallel()
	saveThroughLink(t, func(t *testing.T, root string) (string, string, string) {
		linkTo := filepath.Join("made", "later", "config.yaml")
		link(t, linkTo, filepath.Join(root, "link.yaml"))
		return filepath.Join(root, "link.yaml"), filepath.Join(root, "made", "later", "config.yaml"), linkTo
	}, false)
}

func TestSave_FollowsAChainOfSymlinks(t *testing.T) {
	t.Parallel()
	saveThroughLink(t, func(t *testing.T, root string) (string, string, string) {
		mkdirs(t, filepath.Join(root, "real"))
		link(t, "hop2.yaml", filepath.Join(root, "hop1.yaml"))
		link(t, filepath.Join("real", "config.yaml"), filepath.Join(root, "hop2.yaml"))
		return filepath.Join(root, "hop1.yaml"), filepath.Join(root, "real", "config.yaml"), "hop2.yaml"
	}, true)
}

func TestSave_ALinkLoopIsAnError(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a, b := filepath.Join(root, "a.yaml"), filepath.Join(root, "b.yaml")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	err := configedit.Save(a, []byte("x\n"), configedit.SaveOptions{})
	if err == nil || !strings.Contains(err.Error(), a) {
		t.Errorf("err = %v, want one naming %s", err, a)
	}
}

func TestSave_AFailureInAReadOnlyDirectoryShowsReasonAndPathAndLeavesTheFile(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := configedit.Save(path, []byte("new\n"), configedit.SaveOptions{})
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("err = %v, want the path and the reason", err)
	}
	if got := read(t, path); got != "old\n" {
		t.Errorf("file = %q", got)
	}
	if got := names(t, dir); !slices.Equal(got, []string{"config.yaml"}) {
		t.Errorf("directory holds %v", got)
	}
}

func TestSave_AFailedRenameShowsReasonAndPathAndLeavesTheFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fail := func(oldpath, newpath string) error {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EXDEV}
	}
	err := configedit.Save(path, []byte("new\n"), configedit.SaveOptions{Rename: fail})
	if err == nil {
		t.Fatal("Save succeeded")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), syscall.EXDEV.Error()) {
		t.Errorf("err = %v, want the path and the reason", err)
	}
	if strings.Contains(err.Error(), ".tmp") {
		t.Errorf("err = %v names the temp file", err)
	}
	if got, m := read(t, path), mode(t, path); got != "old\n" || m != 0o644 {
		t.Errorf("file = %q mode %o, want it unchanged", got, m)
	}
	if got := names(t, dir); !slices.Equal(got, []string{"config.yaml"}) {
		t.Errorf("directory holds %v, want the temp file removed", got)
	}
}

func TestSave_APathThatIsADirectoryFails(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := configedit.Save(dir, []byte("new\n"), configedit.SaveOptions{})
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Errorf("err = %v", err)
	}
	if got := names(t, filepath.Dir(dir)); !slices.Equal(got, []string{"config.yaml"}) {
		t.Errorf("directory holds %v", got)
	}
}

func TestSave_ErrorsUnwrapToTheCause(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	path := filepath.Join(t.TempDir(), "c.yaml")
	err := configedit.Save(path, []byte("x"), configedit.SaveOptions{Rename: func(string, string) error { return boom }})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v does not wrap the rename error", err)
	}
}

// startChild launches a save subprocess and optionally blocks at a fault checkpoint.
func startChild(t *testing.T, path, fault string) (*exec.Cmd, string) {
	t.Helper()
	ff := filepath.Join(t.TempDir(), "fault")
	cmd := exec.Command(os.Args[0], "save-child", path, "new: content\n")
	cmd.Env = slices.DeleteFunc(cmd.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "NYX_") })
	if fault != "" {
		cmd.Env = append(cmd.Env, "NYX_FAULT="+fault, "NYX_FAULT_FILE="+ff)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd, ff
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the child never reached the fault point")
}

// crashDuringSave kills before temporary-file content is written and verifies the original file
// or original absence.
func crashDuringSave(t *testing.T, old *string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "config.yaml")
	if old != nil {
		mkdirs(t, filepath.Dir(path))
		if err := os.WriteFile(path, []byte(*old), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd, ff := startChild(t, path, "in-config-save")
	waitForFile(t, ff)
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	got, err := os.ReadFile(path)
	switch {
	case old != nil && (err != nil || string(got) != *old):
		t.Errorf("config file = %q (%v), want the old one", got, err)
	case old == nil && err == nil:
		t.Errorf("config file = %q, want none", got)
	}
	// What is left beside it is the temp file, still empty, never the config file itself.
	for _, n := range names(t, filepath.Dir(path)) {
		if n != "config.yaml" && (!strings.HasSuffix(n, ".tmp") || read(t, filepath.Join(filepath.Dir(path), n)) != "") {
			t.Errorf("unexpected leftover %q", n)
		}
	}
	// A later save is unaffected.
	if err := configedit.Save(path, []byte("later\n"), configedit.SaveOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, path); got != "later\n" {
		t.Errorf("after the crash: %q", got)
	}
}

func TestSave_ACrashLeavesTheOldFile(t *testing.T) {
	t.Parallel()
	crashDuringSave(t, new("old: content\n"))
}

func TestSave_ACrashBeforeTheFirstSaveLeavesNoFile(t *testing.T) {
	t.Parallel()
	crashDuringSave(t, nil)
}

func TestSave_ARunToTheEndWritesTheNewContent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	cmd, _ := startChild(t, path, "")
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if got := read(t, path); got != "new: content\n" {
		t.Errorf("content = %q", got)
	}
}
