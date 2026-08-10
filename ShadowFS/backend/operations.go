// Package backend provides a FUSE-independent MVCC layer that tracks
// filesystem mutations as per-epoch FileVersions on top of a staging area.
//
// Every FUSE mutation creates a FileVersion owned by one epoch (see
// version.go). This file holds the PHYSICAL primitives:
//
//   - promoteVersion: apply an object's visible-head version to the backing
//     (orig) filesystem at finalization time. Idempotent, fail-closed on
//     fsync errors.
//   - movePath / copyFileContents: durable move helpers used by promotion
//     (rename with cross-device and directory fallbacks).
//
// Rollback needs no per-version physical primitive: an epoch's versions live
// in its private staging directory, which is removed wholesale when the
// epoch rolls back; visibility is corrected by dropping the versions from
// the in-memory chain (re-exposing the predecessor).
package backend

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// promoteVersion applies a single visible-head version to the backing
// filesystem. Called only at finalization time, when every owner in the
// object's chain is authorized. Idempotent: a re-run after a crash is safe.
//
// Crash-consistency barrier: the promoted data AND the affected directory
// entries must reach stable storage BEFORE the owning epoch may transition to
// Finalized. An fsync error is therefore a promotion failure (fail closed —
// the epoch stays fenced and the promote is retried).
func promoteVersion(v *FileVersion) error {
	orig := v.LogicalPath
	parent := filepath.Dir(orig)
	switch v.Operation {
	case OpWhiteout:
		if v.Dir {
			if err := os.RemoveAll(orig); err != nil {
				return fmt.Errorf("promote rmdir %q: %w", orig, err)
			}
		} else {
			if err := os.Remove(orig); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("promote unlink %q: %w", orig, err)
			}
		}
		if err := fsyncDir(parent); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("promote whiteout fsync parent %q: %w", parent, err)
		}
		return nil

	case OpMkdir:
		mode := os.FileMode(v.Mode)
		if mode == 0 {
			mode = 0o755
		}
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("promote mkdir parent: %w", err)
		}
		if err := os.Mkdir(orig, mode); err != nil && !os.IsExist(err) {
			return fmt.Errorf("promote mkdir %q: %w", orig, err)
		}
		if err := fsyncDir(parent); err != nil {
			return fmt.Errorf("promote mkdir fsync parent %q: %w", parent, err)
		}
		return nil

	case OpLink:
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("promote link mkdir parent: %w", err)
		}
		// If the target's own version has not promoted yet, LinkTarget is
		// still missing; returning the error keeps this link pending so
		// tryPromoteAll retries it after the target promotes in a later
		// fixpoint iteration. EEXIST means a prior run already linked it.
		if err := os.Link(v.LinkTarget, orig); err != nil && !os.IsExist(err) {
			return fmt.Errorf("promote link %q -> %q: %w", v.LinkTarget, orig, err)
		}
		if err := fsyncDir(parent); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("promote link fsync parent %q: %w", parent, err)
		}
		return nil

	case OpMknod:
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("promote mknod mkdir parent: %w", err)
		}
		if err := syscall.Mknod(orig, v.Mode, int(v.Rdev)); err != nil {
			if !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("promote mknod %q (mode=%#o): %w", orig, v.Mode, err)
			}
		}
		if err := fsyncDir(parent); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("promote mknod fsync parent %q: %w", parent, err)
		}
		return nil

	default: // OpWrite / OpXattr: content-bearing stage payload
		st, err := os.Lstat(v.StagePath)
		if err != nil {
			if os.IsNotExist(err) {
				// Stage payload already consumed by an earlier (crashed)
				// promotion run — idempotent no-op.
				return nil
			}
			return err
		}
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("promote write mkdir parent: %w", err)
		}
		if err := movePath(v.StagePath, orig); err != nil {
			return fmt.Errorf("promote write %q -> %q: %w", v.StagePath, orig, err)
		}
		if st.Mode().IsRegular() {
			if err := fsyncFile(orig); err != nil {
				return fmt.Errorf("promote write fsync file %q: %w", orig, err)
			}
		}
		if err := fsyncDir(parent); err != nil {
			return fmt.Errorf("promote write fsync dest dir %q: %w", parent, err)
		}
		if err := fsyncDir(filepath.Dir(v.StagePath)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("promote write fsync src dir %q: %w", filepath.Dir(v.StagePath), err)
		}
		return nil
	}
}

// movePath moves src to dst. It first attempts an atomic rename(2); if that
// fails with EXDEV (src and dst live on different mount points), it falls
// back to copying the contents and then removing the source. Handles regular
// files, symlinks and directory trees (the last for rename-of-directory
// promotions).
//
// This is required because ShadowFS's staging area and the backing store can
// live on separate mounts — e.g. the backing store is exposed via a bind
// mount — in which case rename(2) returns EXDEV even when the underlying
// filesystem is the same. Without this fallback, promote would fail and lose
// the committed data.
func movePath(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	switch {
	case st.IsDir():
		if err := copyUpDir(src, dst); err != nil {
			return err
		}
		if err := os.RemoveAll(src); err != nil {
			return fmt.Errorf("remove source dir after cross-device copy %q: %w", src, err)
		}
	case st.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		os.Remove(dst)
		if err := os.Symlink(target, dst); err != nil {
			return err
		}
		if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove source symlink after cross-device copy %q: %w", src, err)
		}
	default:
		if err := copyFileContents(src, dst); err != nil {
			return err
		}
		if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove source after cross-device copy %q: %w", src, err)
		}
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
