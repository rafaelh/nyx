package configedit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/fault"
)

// maxLinkHops bounds symlink resolution at the Linux kernel's 40-hop limit.
const maxLinkHops = 40

// errTooManyLinks uses standard symlink-loop wording.
var errTooManyLinks = errors.New("too many levels of symbolic links")

// SaveOptions supplies file-operation hooks for tests.
type SaveOptions struct {
	// NoFsync avoids costly macOS drive-cache flushes in tests.
	NoFsync bool
	// Rename injects final-replacement failures; nil uses os.Rename.
	Rename func(oldpath, newpath string) error
}

// SaveError preserves the original config path and failure cause.
type SaveError struct {
	Path string
	Err  error
}

func (e *SaveError) Error() string { return "cannot save " + e.Path + ": " + config.ErrorText(e.Err) }
func (e *SaveError) Unwrap() error { return e.Err }

// Reason omits the path for UIs displaying it separately.
func (e *SaveError) Reason() string { return config.ErrorText(e.Err) }

// Save atomically replaces a config file so crashes leave a complete old or new file. Symlinks
// are followed, including dangling links, without replacing the link. Created directories and
// the saved file are owner-only; existing broad file permissions are tightened. Failures leave
// the file unchanged and remove temporary files.
func Save(path string, data []byte, opts SaveOptions) (err error) {
	defer func() {
		if err != nil {
			err = &SaveError{Path: path, Err: err}
		}
	}()
	target, err := resolveLinks(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.tmp") // 0600, O_EXCL
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	fault.Point("in-config-save")
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if !opts.NoFsync {
		if err := tmp.Sync(); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	rename := os.Rename
	if opts.Rename != nil {
		rename = opts.Rename
	}
	if err := rename(tmp.Name(), target); err != nil {
		return err
	}
	done = true
	if !opts.NoFsync {
		syncDir(dir)
	}
	return nil
}

// resolveLinks follows symlinks relative to each link's directory. A dangling link resolves to
// its intended target path.
func resolveLinks(path string) (string, error) {
	for hops := 0; ; hops++ {
		fi, err := os.Lstat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return path, nil
		case err != nil:
			return "", err
		case fi.Mode()&os.ModeSymlink == 0:
			return path, nil
		case hops >= maxLinkHops:
			return "", &os.PathError{Op: "readlink", Path: path, Err: errTooManyLinks}
		}
		dest, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(dest) {
			dest = filepath.Join(filepath.Dir(path), dest)
		}
		path = dest
	}
}

// syncDir best-effort syncs rename metadata after replacement so directory changes survive
// power loss.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
