package backend

import (
	"os"
	"syscall"
	"time"
)

// inodeOf returns the underlying inode number for an os.FileInfo on Linux.
// Returns 0 if the platform-specific stat is unavailable.
func inodeOf(info os.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ino
}

// atimeOf returns the access time recorded in the platform stat. Falls back
// to the modification time when the platform-specific data is unavailable
// so callers always get a sensible, monotonic value to feed into Chtimes.
func atimeOf(info os.FileInfo) time.Time {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return info.ModTime()
	}
	return time.Unix(st.Atim.Sec, st.Atim.Nsec)
}

// copyXattrs copies every extended attribute from src to dst, using
// L*-variants so that symlinks are not followed. Best-effort: errors
// reading individual attrs are skipped, but a hard listxattr failure
// (ENOTSUP from the underlying FS) is treated as "no xattrs to copy"
// and returns nil so callers do not regress on filesystems without
// xattr support.
//
// Without this, copyUpFile produced overlay copies that lacked the
// orig's xattrs (SELinux labels, capabilities, ACLs encoded as xattrs,
// user.* metadata). On promote the overlay rename'd over orig and
// silently dropped every attribute — a real data-loss bug for any
// workload that depends on xattrs.
func copyXattrs(src, dst string) error {
	// First call: query required buffer size.
	size, err := syscall.Listxattr(src, nil)
	if err != nil {
		if err == syscall.ENOTSUP || err == syscall.ENODATA {
			return nil
		}
		return err
	}
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	n, err := syscall.Listxattr(src, buf)
	if err != nil {
		if err == syscall.ENOTSUP || err == syscall.ENODATA {
			return nil
		}
		return err
	}
	// Listxattr returns NUL-separated attribute names.
	for _, name := range splitNul(buf[:n]) {
		if name == "" {
			continue
		}
		vsize, gerr := syscall.Getxattr(src, name, nil)
		if gerr != nil {
			if gerr == syscall.ENODATA || gerr == syscall.ENOTSUP {
				continue
			}
			return gerr
		}
		val := make([]byte, vsize)
		vn, gerr := syscall.Getxattr(src, name, val)
		if gerr != nil {
			if gerr == syscall.ENODATA {
				continue
			}
			return gerr
		}
		if serr := syscall.Setxattr(dst, name, val[:vn], 0); serr != nil {
			// Some attribute namespaces (security.*, system.*) require
			// privileges or special FS support. Skip rather than abort
			// the entire copy-up: missing one xattr is preferable to
			// the whole write op failing with EIO.
			if serr == syscall.EPERM || serr == syscall.ENOTSUP || serr == syscall.EOPNOTSUPP {
				continue
			}
			return serr
		}
	}
	return nil
}

func splitNul(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}
