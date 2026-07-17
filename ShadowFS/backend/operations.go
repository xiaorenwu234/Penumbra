// Package backend provides a FUSE-independent layer for tracking directory
// operations on top of a shared overlay (copy-on-write) staging area.
//
// All FUSE mutations are recorded as LogEntry values. Each entry knows how
// to:
//   - Rollback: discard its overlay artefact so the orig filesystem view
//     remains untouched.
//   - Promote: apply the overlay artefact to the orig filesystem.
//
// Rollback is invoked when an agent (or any agent depending on it) is
// rolled back. Promote is invoked once *all* writers of the affected path
// have committed and their upstream dependencies are finalized.
package backend

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// LogEntry is the interface implemented by every overlay log entry.
type LogEntry interface {
	Seq() int64
	Path() string    // logical (orig) path of the affected file/dir
	Rollback() error // discard this entry's overlay artefact
	Promote() error  // apply this entry's overlay artefact to the orig FS
}

// baseEntry holds the global sequence number shared by all entries.
type baseEntry struct {
	SeqNum int64
}

func (b *baseEntry) Seq() int64 { return b.SeqNum }

// --- Entry types ---

// OverlayWriteEntry describes either a freshly created or modified file.
// The overlay copy contains the new contents; promotion moves it onto the
// orig path; rollback simply deletes the overlay copy.
//
// If the write replaced a prior whiteout (i.e. another agent had deleted the
// file first), HadWhiteout is true and WhiteoutPath records the marker path
// so that Rollback can restore it.
type OverlayWriteEntry struct {
	baseEntry
	OrigPath     string
	OverlayPath  string
	HadWhiteout  bool   // true if PrepareWrite removed an existing whiteout
	WhiteoutPath string // whiteout marker path (only meaningful when HadWhiteout)
	OrigSize     int64  // orig file size at copy-up time (for redo partial-write detection)
}

func (e *OverlayWriteEntry) Path() string { return e.OrigPath }

func (e *OverlayWriteEntry) Rollback() error {
	if err := os.Remove(e.OverlayPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rollback overlay write %q: %w", e.OverlayPath, err)
	}
	// If this write had cleared a whiteout created by an upstream agent,
	// restore the whiteout so the upstream agent's delete intent survives.
	if e.HadWhiteout && e.WhiteoutPath != "" {
		if err := os.MkdirAll(filepath.Dir(e.WhiteoutPath), 0o755); err != nil {
			return fmt.Errorf("rollback restore whiteout mkdir %q: %w", e.WhiteoutPath, err)
		}
		f, err := os.OpenFile(e.WhiteoutPath, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("rollback restore whiteout %q: %w", e.WhiteoutPath, err)
		}
		f.Close()
	}
	return nil
}

func (e *OverlayWriteEntry) Promote() error {
	if _, err := os.Lstat(e.OverlayPath); err != nil {
		if os.IsNotExist(err) {
			return nil // already promoted by another entry sharing this overlay
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.OrigPath), 0o755); err != nil {
		return fmt.Errorf("promote overlay write mkdir parent: %w", err)
	}
	if err := moveFile(e.OverlayPath, e.OrigPath); err != nil {
		return fmt.Errorf("promote overlay write %q -> %q: %w", e.OverlayPath, e.OrigPath, err)
	}
	return nil
}

// moveFile moves src to dst. It first attempts an atomic rename(2); if that
// fails with EXDEV (src and dst live on different mount points / filesystems),
// it falls back to copying the contents and then removing the source.
//
// This is required because ShadowFS's staging area and the backing store can
// live on separate mounts — e.g. the backing store is exposed via a bind mount
// — in which case rename(2) returns EXDEV even when the underlying filesystem
// is the same. Without this fallback, promote would fail and the caller would
// still drop the overlay copy, silently losing the committed data.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyFileContents(src, dst); err != nil {
		return err
	}
	if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove source after cross-device copy %q: %w", src, err)
	}
	return nil
}

// copyFileContents copies src to dst (truncating dst), preserving the source
// file's permission bits, and fsyncs before returning so the promoted data is
// durable.
func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// OverlayMkdirEntry describes a directory created in the overlay view.
type OverlayMkdirEntry struct {
	baseEntry
	OrigPath     string
	OverlayPath  string
	Mode         uint32
	HadWhiteout  bool   // true if RecordMkdir removed an existing whiteout
	WhiteoutPath string // whiteout marker path (only meaningful when HadWhiteout)
}

func (e *OverlayMkdirEntry) Path() string { return e.OrigPath }

func (e *OverlayMkdirEntry) Rollback() error {
	// Use RemoveAll to handle the case where overlay children were created
	// by dependent agents whose cascade rollback already ran but left
	// residual files (e.g. due to timing or edge cases in the dep graph).
	// Previously we used os.Remove and silently swallowed ENOTEMPTY, which
	// leaked orphan overlay directories.
	if err := os.RemoveAll(e.OverlayPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rollback overlay mkdir %q: %w", e.OverlayPath, err)
	}
	// Restore whiteout if one was cleared before the mkdir.
	if e.HadWhiteout && e.WhiteoutPath != "" {
		if err := os.MkdirAll(filepath.Dir(e.WhiteoutPath), 0o755); err != nil {
			return fmt.Errorf("rollback restore mkdir whiteout mkdir %q: %w", e.WhiteoutPath, err)
		}
		f, err := os.OpenFile(e.WhiteoutPath, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("rollback restore mkdir whiteout %q: %w", e.WhiteoutPath, err)
		}
		f.Close()
	}
	return nil
}

func (e *OverlayMkdirEntry) Promote() error {
	mode := os.FileMode(e.Mode)
	if mode == 0 {
		mode = 0o755
	}
	if err := os.MkdirAll(filepath.Dir(e.OrigPath), 0o755); err != nil {
		return fmt.Errorf("promote mkdir parent: %w", err)
	}
	if err := os.Mkdir(e.OrigPath, mode); err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("promote mkdir %q: %w", e.OrigPath, err)
	}
	return nil
}

// OverlayUnlinkEntry describes a file deletion. A whiteout marker hides
// the file in the overlay view; on promote the orig file is removed.
type OverlayUnlinkEntry struct {
	baseEntry
	OrigPath     string
	WhiteoutPath string
	OverlayPath  string // may hold a stale overlay copy that needs cleanup on promote
}

func (e *OverlayUnlinkEntry) Path() string { return e.OrigPath }

func (e *OverlayUnlinkEntry) Rollback() error {
	if err := os.Remove(e.WhiteoutPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rollback unlink whiteout %q: %w", e.WhiteoutPath, err)
	}
	return nil
}

func (e *OverlayUnlinkEntry) Promote() error {
	if err := os.Remove(e.OrigPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("promote unlink %q: %w", e.OrigPath, err)
	}
	if e.OverlayPath != "" {
		if err := os.Remove(e.OverlayPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("promote unlink cleanup overlay %q: %w", e.OverlayPath, err)
		}
	}
	if err := os.Remove(e.WhiteoutPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("promote unlink cleanup whiteout %q: %w", e.WhiteoutPath, err)
	}
	return nil
}

// OverlayRmdirEntry describes a directory removal. Like unlink, a whiteout
// hides the directory; promotion deletes the orig directory tree.
type OverlayRmdirEntry struct {
	baseEntry
	OrigPath     string
	WhiteoutPath string
	OverlayPath  string
}

func (e *OverlayRmdirEntry) Path() string { return e.OrigPath }

func (e *OverlayRmdirEntry) Rollback() error {
	if err := os.Remove(e.WhiteoutPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rollback rmdir whiteout %q: %w", e.WhiteoutPath, err)
	}
	return nil
}

func (e *OverlayRmdirEntry) Promote() error {
	if err := os.RemoveAll(e.OrigPath); err != nil {
		return fmt.Errorf("promote rmdir %q: %w", e.OrigPath, err)
	}
	if e.OverlayPath != "" {
		os.RemoveAll(e.OverlayPath)
	}
	if err := os.Remove(e.WhiteoutPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("promote rmdir cleanup whiteout %q: %w", e.WhiteoutPath, err)
	}
	return nil
}

// --- Serialization ---

// SerializableEntry is a flat JSON-friendly representation of any LogEntry.
type SerializableEntry struct {
	Type         string `json:"type"` // "write","mkdir","unlink","rmdir"
	SeqNum       int64  `json:"seq"`
	OrigPath     string `json:"orig_path,omitempty"`
	OverlayPath  string `json:"overlay_path,omitempty"`
	WhiteoutPath string `json:"whiteout_path,omitempty"`
	Mode         uint32 `json:"mode,omitempty"`
	HadWhiteout  bool   `json:"had_whiteout,omitempty"`
	// OrigSize records the size of the orig file at copy-up time so that
	// redoEntry can detect a partially-written overlay file after a crash
	// between copyUpFile and its fsync.
	OrigSize int64 `json:"orig_size,omitempty"`
}

// MarshalEntry converts a LogEntry to its serializable form.
func MarshalEntry(e LogEntry) SerializableEntry {
	switch v := e.(type) {
	case *OverlayWriteEntry:
		se := SerializableEntry{Type: "write", SeqNum: v.SeqNum, OrigPath: v.OrigPath, OverlayPath: v.OverlayPath, OrigSize: v.OrigSize}
		if v.HadWhiteout {
			se.WhiteoutPath = v.WhiteoutPath
			se.HadWhiteout = true
		}
		return se
	case *OverlayMkdirEntry:
		se := SerializableEntry{Type: "mkdir", SeqNum: v.SeqNum, OrigPath: v.OrigPath, OverlayPath: v.OverlayPath, Mode: v.Mode}
		if v.HadWhiteout {
			se.WhiteoutPath = v.WhiteoutPath
			se.HadWhiteout = true
		}
		return se
	case *OverlayUnlinkEntry:
		return SerializableEntry{Type: "unlink", SeqNum: v.SeqNum, OrigPath: v.OrigPath, OverlayPath: v.OverlayPath, WhiteoutPath: v.WhiteoutPath}
	case *OverlayRmdirEntry:
		return SerializableEntry{Type: "rmdir", SeqNum: v.SeqNum, OrigPath: v.OrigPath, OverlayPath: v.OverlayPath, WhiteoutPath: v.WhiteoutPath}
	default:
		return SerializableEntry{}
	}
}

// UnmarshalEntry converts a SerializableEntry back to a concrete LogEntry.
// Returns nil if the type is unrecognized.
func UnmarshalEntry(s SerializableEntry) LogEntry {
	switch s.Type {
	case "write":
		return &OverlayWriteEntry{
			baseEntry:    baseEntry{SeqNum: s.SeqNum},
			OrigPath:     s.OrigPath,
			OverlayPath:  s.OverlayPath,
			HadWhiteout:  s.HadWhiteout,
			WhiteoutPath: s.WhiteoutPath,
			OrigSize:     s.OrigSize,
		}
	case "mkdir":
		return &OverlayMkdirEntry{
			baseEntry:    baseEntry{SeqNum: s.SeqNum},
			OrigPath:     s.OrigPath,
			OverlayPath:  s.OverlayPath,
			Mode:         s.Mode,
			HadWhiteout:  s.HadWhiteout,
			WhiteoutPath: s.WhiteoutPath,
		}
	case "unlink":
		return &OverlayUnlinkEntry{baseEntry: baseEntry{SeqNum: s.SeqNum}, OrigPath: s.OrigPath, OverlayPath: s.OverlayPath, WhiteoutPath: s.WhiteoutPath}
	case "rmdir":
		return &OverlayRmdirEntry{baseEntry: baseEntry{SeqNum: s.SeqNum}, OrigPath: s.OrigPath, OverlayPath: s.OverlayPath, WhiteoutPath: s.WhiteoutPath}
	default:
		return nil
	}
}
