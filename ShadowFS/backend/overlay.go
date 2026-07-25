package backend

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Staging layout (v2, per-epoch MVCC):
//
//	staging/
//	  epochs/<escaped-epoch-id>/files/<rel-path>   # private version files
//	  epochs/<escaped-epoch-id>/files/<dir>/.shadow.wh.<name>
//	                                               # debug whiteout markers
//	  metadata/.shadow_state.json                  # v2 checkpoint
//	  metadata/.shadow_wal                         # v2 WAL
//
// Visibility is decided by the in-memory version graph (visibleHead +
// Resolve), NOT by probing the staging tree; the per-epoch files are only
// version payload carriers. Whiteout markers are written for debuggability
// but are never consulted for visibility.

const (
	epochsDirName   = "epochs"
	metadataDirName = "metadata"
	epochFilesDir   = "files"
	// whiteoutPrefix names the debug marker recorded next to a whiteout
	// version's would-be stage path.
	whiteoutPrefix = ".shadow.wh."
)

// metadataDir returns the staging metadata directory (checkpoint + WAL).
func metadataDir(stagingDir string) string {
	return filepath.Join(stagingDir, metadataDirName)
}

// epochDirFor maps an epoch to its private staging directory. Epoch IDs may
// contain path separators (e.g. "implicit:/sys/fs/cgroup/..."), so the ID is
// path-escaped to a single component.
func epochDirFor(stagingDir string, epochID EpochID) string {
	return filepath.Join(stagingDir, epochsDirName, url.PathEscape(string(epochID)))
}

// relFromTracked returns origPath relative to trackedDir. Returns "" for the
// root itself. The result uses filepath.Separator and is "Clean".
func relFromTracked(trackedDir, origPath string) (string, error) {
	rel, err := filepath.Rel(trackedDir, origPath)
	if err != nil {
		return "", fmt.Errorf("relFromTracked %q vs %q: %w", trackedDir, origPath, err)
	}
	// Reject only true escapes: rel == ".." or starts with "../".
	// A bare HasPrefix("..") would also reject legitimate filenames
	// inside trackedDir whose first component starts with ".."
	// (e.g. "..backup/file").
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes tracked dir %q", origPath, trackedDir)
	}
	if rel == "." {
		return "", nil
	}
	return rel, nil
}

// stagePathFor maps an orig path to the given epoch's private version file.
func stagePathFor(stagingDir, trackedDir string, epochID EpochID, origPath string) (string, error) {
	rel, err := relFromTracked(trackedDir, origPath)
	if err != nil {
		return "", err
	}
	if rel == "" {
		return "", fmt.Errorf("cannot version the tracked root itself")
	}
	return filepath.Join(epochDirFor(stagingDir, epochID), epochFilesDir, rel), nil
}

// whiteoutMarkerFor maps an orig path to the epoch's debug whiteout marker.
func whiteoutMarkerFor(stagingDir, trackedDir string, epochID EpochID, origPath string) (string, error) {
	rel, err := relFromTracked(trackedDir, origPath)
	if err != nil {
		return "", err
	}
	if rel == "" {
		return "", fmt.Errorf("cannot whiteout the tracked root itself")
	}
	dir, base := filepath.Split(rel)
	return filepath.Join(epochDirFor(stagingDir, epochID), epochFilesDir, dir, whiteoutPrefix+base), nil
}

// ensureParentDir makes sure the parent directory of path exists.
func ensureParentDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o755)
}

// writeWhiteoutMarker creates the epoch's debug whiteout marker. Idempotent;
// best-effort callers may ignore the error.
func writeWhiteoutMarker(markerPath string) error {
	if err := ensureParentDir(markerPath); err != nil {
		return fmt.Errorf("whiteout marker mkdirs: %w", err)
	}
	f, err := os.OpenFile(markerPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("whiteout marker create %q: %w", markerPath, err)
	}
	return f.Close()
}

// copyUpFile copies the contents of src (a backing file or another version's
// stage file) to dst, creating intermediate directories as needed. The
// destination's mode and timestamps mirror the source. Symlinks are preserved
// verbatim. Special files (device / pipe / socket) are rejected with
// syscall.EOPNOTSUPP because io.Copy on them would block indefinitely or
// produce a meaningless copy.
//
// ATOMIC: the payload is written to a temp name and rename(2)d onto dst, so
// dst either does not exist or is a COMPLETE copy. WAL-replay redo relies on
// this: "stage file exists" means "copy-up finished", and user writes made
// after the copy-up are never clobbered by a re-copy.
func copyUpFile(src, dst string) error {
	// Use Lstat to detect symlinks without following them.
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if err := ensureParentDir(dst); err != nil {
		return err
	}
	mode := st.Mode()
	// Preserve symlinks instead of following them.
	if mode&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		// Replace any stale dst (idempotent redo may re-run the copy).
		os.Remove(dst)
		if err := os.Symlink(target, dst); err != nil {
			return err
		}
		// Best-effort ownership preservation on the symlink itself.
		if st, ok := st.Sys().(*syscall.Stat_t); ok {
			_ = syscall.Lchown(dst, int(st.Uid), int(st.Gid))
		}
		return nil
	}
	// Reject anything that is not a regular file. Devices, pipes, sockets,
	// etc. cannot be meaningfully copied via read/write and would either
	// block io.Copy forever or silently produce an empty copy.
	if !mode.IsRegular() {
		return fmt.Errorf("copy-up unsupported file type for %q (mode %v): %w",
			src, mode, syscall.EOPNOTSUPP)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".shadow-cptmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	// fsync BEFORE the rename so the payload is durable when the atomic
	// rename publishes it. A crash mid-copy leaves only the temp file, which
	// the redo path ignores (dst absent -> re-copy).
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync stage copy %q: %w", tmp, err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// Preserve ownership so promotion does not silently change the file's
	// uid/gid to the FUSE process's identity.
	if st, ok := st.Sys().(*syscall.Stat_t); ok {
		if err := syscall.Lchown(tmp, int(st.Uid), int(st.Gid)); err != nil && err != syscall.EPERM {
			os.Remove(tmp)
			return fmt.Errorf("lchown stage copy %q: %w", tmp, err)
		}
	}
	// Preserve atime/mtime so that a subsequent promotion does not silently
	// bump the user-visible modification time.
	if err := os.Chtimes(tmp, atimeOf(st), st.ModTime()); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("chtimes stage copy %q: %w", tmp, err)
	}
	// Copy extended attributes (SELinux labels, file caps, ACLs, user.*).
	// Without this, promotion would install a file stripped of every xattr
	// the source carried.
	if err := copyXattrs(src, tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("copy xattrs %q -> %q: %w", src, tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("publish stage copy %q: %w", dst, err)
	}
	return nil
}

// copyUpDir recursively copies the directory tree rooted at src into dst.
// Symlinks are recreated; regular files are copied; directories preserve
// their mode. Used to materialize a rename of a directory into the acting
// epoch's stage tree.
func copyUpDir(src, dst string) error {
	stat, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return fmt.Errorf("copyUpDir: %q is not a directory", src)
	}
	if err := os.MkdirAll(dst, stat.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		info, err := e.Info()
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := copyUpDir(s, d); err != nil {
				return err
			}
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(s)
			if err != nil {
				return err
			}
			os.Remove(d)
			if err := os.Symlink(target, d); err != nil {
				return err
			}
		default:
			if err := copyUpFile(s, d); err != nil {
				return err
			}
		}
	}
	return nil
}

// MergedDirEntry describes a single entry in the merged version+backing view.
type MergedDirEntry struct {
	Name string
	Mode os.FileMode
	Ino  uint64
}
