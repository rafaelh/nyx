package configedit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/fault"
)

// maxLinkHops is how many symbolic links Save follows to the file it writes, as the kernel allows
// (40 on Linux).
const maxLinkHops = 40

// errTooManyLinks is the reason for a link chain longer than maxLinkHops, worded as the kernel does.
var errTooManyLinks = errors.New("too many levels of symbolic links")

// SaveOptions are the knobs of Save a test turns.
type SaveOptions struct {
	// NoFsync skips the fsync of the file and its directory, for tests: an fsync on macOS flushes
	// the whole drive cache.
	NoFsync bool
	// Rename replaces os.Rename, so a test can make the last step fail. nil means os.Rename.
	Rename func(oldpath, newpath string) error
}

// SaveError is a save that failed: the config path as the caller gave it, and the cause.
type SaveError struct {
	Path string
	Err  error
}

func (e *SaveError) Error() string { return "cannot save " + e.Path + ": " + config.ErrorText(e.Err) }
func (e *SaveError) Unwrap() error { return e.Err }

// Reason is why the save failed, without the path, for a caller that shows the path on its own.
func (e *SaveError) Reason() string { return config.ErrorText(e.Err) }

// Save writes data to the config file at path, replacing it atomically: a crash leaves the old file
// or the new one, never a part of either. A symbolic link at path is followed, so the file it
// points to is replaced and the link stays; a dangling one creates its target. Missing directories
// are created readable by their owner only, and the file is always readable by its owner only,
// which tightens a broader one. When it fails the file is unchanged and no temporary file is left.
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

// resolveLinks is the file that path names once its symbolic links are followed. A link is
// resolved against its own directory, and a dangling one leads to the file it names.
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

// syncDir flushes a directory's entries, so a rename in it survives a power cut. It is best effort:
// the file is already in place.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
