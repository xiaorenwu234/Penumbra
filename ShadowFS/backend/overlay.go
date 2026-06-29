package backend

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// whiteoutPrefix marks a file or directory as deleted in the overlay view.
// A whiteout is an empty regular file at <staging parent>/.shadow.wh.<basename>.
const whiteoutPrefix = ".shadow.wh."

// overlayKind enumerates the possible states of a path in the overlay view.
type overlayKind int

const (
	kindNotPresent overlayKind = iota // overlay has neither a copy nor a whiteout
	kindFile                          // overlay holds a regular file
	kindDir                           // overlay holds a directory
	kindSymlink                       // overlay holds a symlink
	kindWhiteout                      // overlay parent has a whiteout for this name
)

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

// overlayPathFor maps an orig path to its staging (overlay) copy path.
// stagingDir IS the overlay root — no intermediate subdirectory.
func overlayPathFor(stagingDir, trackedDir, origPath string) (string, error) {
	rel, err := relFromTracked(trackedDir, origPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(stagingDir, rel), nil
}

// whiteoutPathFor maps an orig path to the whiteout marker path that would
// hide it in the overlay view.
func whiteoutPathFor(stagingDir, trackedDir, origPath string) (string, error) {
	rel, err := relFromTracked(trackedDir, origPath)
	if err != nil {
		return "", err
	}
	if rel == "" {
		return "", fmt.Errorf("cannot whiteout the tracked root itself")
	}
	dir, base := filepath.Split(rel)
	return filepath.Join(stagingDir, dir, whiteoutPrefix+base), nil
}

// hasWhiteout reports whether the given orig path is hidden by a whiteout.
func hasWhiteout(stagingDir, trackedDir, origPath string) bool {
	wp, err := whiteoutPathFor(stagingDir, trackedDir, origPath)
	if err != nil {
		return false
	}
	_, err = os.Lstat(wp)
	return err == nil
}

// writeWhiteout creates an empty whiteout marker for origPath. The parent
// overlay directory is created on demand. Idempotent.
func writeWhiteout(stagingDir, trackedDir, origPath string) error {
	wp, err := whiteoutPathFor(stagingDir, trackedDir, origPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(wp), 0o755); err != nil {
		return fmt.Errorf("whiteout mkdirs: %w", err)
	}
	f, err := os.OpenFile(wp, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("whiteout create %q: %w", wp, err)
	}
	return f.Close()
}

// removeWhiteout removes the whiteout marker for origPath, if present.
// Returns (true, nil) if it removed an existing marker, (false, nil) if
// none existed, (false, err) on unexpected errors.
func removeWhiteout(stagingDir, trackedDir, origPath string) (bool, error) {
	wp, err := whiteoutPathFor(stagingDir, trackedDir, origPath)
	if err != nil {
		return false, err
	}
	if err := os.Remove(wp); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ensureOverlayParent makes sure the parent directory of overlayPath exists.
func ensureOverlayParent(overlayPath string) error {
	return os.MkdirAll(filepath.Dir(overlayPath), 0o755)
}

// copyUpFile copies the contents of orig to overlay, creating intermediate
// directories as needed. The destination's mode and timestamps mirror the
// source. Symlinks are preserved verbatim. Special files (device / pipe /
// socket) are rejected with syscall.EOPNOTSUPP because io.Copy on them
// would block indefinitely or produce a meaningless overlay copy.
func copyUpFile(orig, overlay string) error {
	// Use Lstat to detect symlinks without following them.
	st, err := os.Lstat(orig)
	if err != nil {
		return err
	}
	if err := ensureOverlayParent(overlay); err != nil {
		return err
	}
	mode := st.Mode()
	// Preserve symlinks instead of following them.
	if mode&os.ModeSymlink != 0 {
		target, err := os.Readlink(orig)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, overlay); err != nil {
			return err
		}
		// Best-effort ownership preservation on the symlink itself.
		if st, ok := st.Sys().(*syscall.Stat_t); ok {
			_ = syscall.Lchown(overlay, int(st.Uid), int(st.Gid))
		}
		return nil
	}
	// Reject anything that is not a regular file. Devices, pipes, sockets,
	// etc. cannot be meaningfully copied via read/write and would either
	// block io.Copy forever or silently produce an empty overlay copy.
	if !mode.IsRegular() {
		return fmt.Errorf("copy-up unsupported file type for %q (mode %v): %w",
			orig, mode, syscall.EOPNOTSUPP)
	}
	src, err := os.Open(orig)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(overlay, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(overlay)
		return err
	}
	// fsync BEFORE close so the data is durable on disk. Without this a
	// crash after WAL fsync but before the OS flushes the page cache can
	// leave the overlay file empty or truncated, and redoEntry would skip
	// the copy-up because the file already exists.
	if err := dst.Sync(); err != nil {
		dst.Close()
		return fmt.Errorf("fsync overlay %q: %w", overlay, err)
	}
	if err := dst.Close(); err != nil {
		return err
	}
	// Preserve ownership so promote (rename overlay→orig) does not silently
	// change the file's uid/gid to the FUSE process's identity.
	if st, ok := st.Sys().(*syscall.Stat_t); ok {
		if err := syscall.Lchown(overlay, int(st.Uid), int(st.Gid)); err != nil && err != syscall.EPERM {
			return fmt.Errorf("lchown overlay %q: %w", overlay, err)
		}
	}
	// Preserve atime/mtime so that a subsequent commit-promote (which
	// rename(2)s the overlay copy back over orig) does not silently bump
	// the user-visible modification time. We set timestamps AFTER close
	// so they reflect the final post-copy state, not the page-cache flush.
	if err := os.Chtimes(overlay, atimeOf(st), st.ModTime()); err != nil {
		// Non-fatal: log via returned error so caller can decide. We do
		// not delete the overlay since the data copy itself succeeded;
		// callers that strictly require timestamp fidelity will surface
		// this error.
		return fmt.Errorf("chtimes overlay %q: %w", overlay, err)
	}
	// Copy extended attributes (SELinux labels, file caps, ACLs, user.*).
	// Without this, promote rename'd the overlay over orig and silently
	// stripped every xattr the orig file carried.
	if err := copyXattrs(orig, overlay); err != nil {
		return fmt.Errorf("copy xattrs %q -> %q: %w", orig, overlay, err)
	}
	return nil
}

// lookupOverlay returns the overlay state for origPath: whether it has a
// whiteout, an overlay copy (file/dir/symlink), or nothing.
func lookupOverlay(stagingDir, trackedDir, origPath string) (overlayKind, error) {
	if hasWhiteout(stagingDir, trackedDir, origPath) {
		return kindWhiteout, nil
	}
	op, err := overlayPathFor(stagingDir, trackedDir, origPath)
	if err != nil {
		return kindNotPresent, err
	}
	st, err := os.Lstat(op)
	if err != nil {
		if os.IsNotExist(err) {
			return kindNotPresent, nil
		}
		return kindNotPresent, err
	}
	mode := st.Mode()
	switch {
	case mode.IsDir():
		return kindDir, nil
	case mode&os.ModeSymlink != 0:
		return kindSymlink, nil
	default:
		return kindFile, nil
	}
}

// MergedDirEntry describes a single entry in the merged overlay+orig view.
type MergedDirEntry struct {
	Name string
	Mode os.FileMode
	Ino  uint64
}

// MergeReaddir lists entries in origDir overlaid with overlayDir. Whiteouts
// hide entries from origDir. Overlay entries replace orig entries with the
// same name. Whiteout marker files themselves are not returned.
func MergeReaddir(origDir, overlayDir string) ([]MergedDirEntry, error) {
	whiteouts := make(map[string]struct{})
	overlayEntries := make(map[string]MergedDirEntry)

	if oents, err := os.ReadDir(overlayDir); err == nil {
		for _, e := range oents {
			name := e.Name()
			// Skip internal state file so it never leaks into the merged view.
			if name == stateFileName || name == stateFileName+".tmp" || name == walFileName {
				continue
			}
			if strings.HasPrefix(name, whiteoutPrefix) {
				whiteouts[strings.TrimPrefix(name, whiteoutPrefix)] = struct{}{}
				continue
			}
			info, ierr := e.Info()
			if ierr != nil {
				continue
			}
			overlayEntries[name] = MergedDirEntry{
				Name: name,
				Mode: info.Mode(),
				Ino:  inodeOf(info),
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	result := make([]MergedDirEntry, 0, len(overlayEntries))
	if oents, err := os.ReadDir(origDir); err == nil {
		for _, e := range oents {
			name := e.Name()
			if _, hidden := whiteouts[name]; hidden {
				continue
			}
			if _, replaced := overlayEntries[name]; replaced {
				continue
			}
			info, ierr := e.Info()
			if ierr != nil {
				continue
			}
			result = append(result, MergedDirEntry{
				Name: name,
				Mode: info.Mode(),
				Ino:  inodeOf(info),
			})
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	for _, e := range overlayEntries {
		if _, hidden := whiteouts[e.Name]; hidden {
			continue
		}
		result = append(result, e)
	}
	// Sort by name so the merged result has a deterministic, stable order
	// (os.ReadDir sorts orig entries, but the overlay map iteration is
	// unordered).
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// removeOverlayState deletes any overlay artefacts (file, dir, whiteout)
// associated with origPath. Best-effort: missing files are ignored.
//
// When removeWh is false, the whiteout marker is preserved. This is used
// during promote to avoid deleting a whiteout that belongs to another
// agent's active UnlinkEntry — that entry's own Promote() will clean up
// the whiteout when it runs.
func removeOverlayState(stagingDir, trackedDir, origPath string, removeWh bool) error {
	if op, err := overlayPathFor(stagingDir, trackedDir, origPath); err == nil {
		if st, statErr := os.Lstat(op); statErr == nil {
			if st.IsDir() {
				if err := os.RemoveAll(op); err != nil {
					return err
				}
			} else {
				if err := os.Remove(op); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
	}
	if removeWh {
		if _, err := removeWhiteout(stagingDir, trackedDir, origPath); err != nil {
			return err
		}
	}
	return nil
}
