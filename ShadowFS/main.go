package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"wokron/shadowfs/backend"
)

// cgroupCache memoises successful pid → cgroup-path resolutions.
//
// Reading /proc/<pid>/cgroup from a FUSE handler occasionally returns
// EBADF mid-stream for a process that is alive and whose cgroup is
// otherwise readable. Once the kernel starts returning EBADF for a
// given (pid,fd) it tends to keep doing so for the rest of that
// process's lifetime, which would otherwise split its operations
// across the real cgroup ID and a synthetic "pid-N" ID, breaking
// commit/rollback grouping.
//
// Key is (pid, starttime) so that pid reuse across processes does not
// return stale data. starttime is read from /proc/<pid>/stat field 22
// (jiffies since boot) and is invariant for a process's lifetime.
type cgroupCacheKey struct {
	pid       int
	starttime string
}

var cgroupCache sync.Map // cgroupCacheKey -> string

// shadowBackend is the global rollback backend, initialized in main.
var shadowBackend *backend.Backend

// ctlFileName is the virtual control file at the mount root.
const ctlFileName = ".shadow.ctl"

// OverlayRoot is the shared state of the overlay mount: orig (read-only
// source of truth), overlay (write-side staging) and the backend that owns
// rollback/commit semantics.
type OverlayRoot struct {
	origDir    string
	overlayDir string
}

// OverlayNode is a single inode in the merged orig+overlay view.
type OverlayNode struct {
	fs.Inode
	root *OverlayRoot
}

var (
	_ fs.NodeOnAdder    = (*OverlayNode)(nil)
	_ fs.NodeLookuper   = (*OverlayNode)(nil)
	_ fs.NodeGetattrer  = (*OverlayNode)(nil)
	_ fs.NodeReaddirer  = (*OverlayNode)(nil)
	_ fs.NodeOpener     = (*OverlayNode)(nil)
	_ fs.NodeCreater    = (*OverlayNode)(nil)
	_ fs.NodeMkdirer    = (*OverlayNode)(nil)
	_ fs.NodeRmdirer    = (*OverlayNode)(nil)
	_ fs.NodeUnlinker   = (*OverlayNode)(nil)
	_ fs.NodeRenamer    = (*OverlayNode)(nil)
	_ fs.NodeSetattrer  = (*OverlayNode)(nil)
	_ fs.NodeReadlinker = (*OverlayNode)(nil)
)

// --- Tracked file handle ---

// trackedHandle wraps a go-fuse LoopbackFile with fd tracking. The
// embedded LoopbackFile delegates all file operations (Read, Write,
// Flush, Fsync, etc.) to the raw fd. We override Release so that the
// TrackedFD is closed exactly once — either by a cascade rollback
// (CloseAgentFDs) or by the kernel's RELEASE, whichever comes first.
//
// onOverlay records whether the embedded fd points at an overlay copy
// (true) or directly at the orig file (false). Setattr uses this to
// decide whether the fast-path fh.Setattr is safe: applying chmod /
// chown / utimens / truncate via an orig-bound fd would mutate the
// supposedly-immutable orig file and bypass PrepareWrite entirely.
type trackedHandle struct {
	*fs.LoopbackFile
	tfd       *backend.TrackedFD
	cgroupID  string
	onOverlay bool
}

var _ fs.FileReleaser = (*trackedHandle)(nil)

func (h *trackedHandle) Release(ctx context.Context) syscall.Errno {
	// Unregister from backend so CloseAgentFDs won't double-close.
	shadowBackend.UnregisterFD(h.cgroupID, h.tfd)
	// Close via TrackedFD (idempotent). If rollback already closed it,
	// this is a no-op.
	_ = h.tfd.Close()
	// The inner FileHandle (LoopbackFile) will also try syscall.Close
	// on the raw fd, but since tfd.Close() already closed it, the
	// second close returns EBADF which is silently ignored.
	return h.LoopbackFile.Release(ctx)
}

// --- Path helpers ---

// relPath returns this node's path relative to the mount root.
func (n *OverlayNode) relPath() string { return n.Path(nil) }

// origPath returns the absolute orig-side path for this node.
func (n *OverlayNode) origPath() string {
	return filepath.Join(n.root.origDir, n.relPath())
}

// origChildPath returns the absolute orig-side path for a child name.
func (n *OverlayNode) origChildPath(name string) string {
	return filepath.Join(n.root.origDir, n.relPath(), name)
}

// --- Control file ---

type controlFile struct {
	fs.Inode
}

var (
	_ fs.NodeGetattrer = (*controlFile)(nil)
	_ fs.NodeOpener    = (*controlFile)(nil)
	_ fs.NodeWriter    = (*controlFile)(nil)
)

func (f *controlFile) Getattr(ctx context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	return 0
}

func (f *controlFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	return nil, fuse.FOPEN_DIRECT_IO, 0
}

// Write handles writes to the control file. Recognized commands:
//
//	"r <cgroup-id>" — rollback the specified agent (and its rollback group)
//	"c <cgroup-id>" — commit (clear the undo log) for the specified agent
func (f *controlFile) Write(ctx context.Context, _ fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	cmd := strings.TrimSpace(string(data))
	parts := strings.Fields(cmd)
	if len(parts) != 2 {
		return 0, syscall.EINVAL
	}
	action, cgroupID := parts[0], parts[1]
	switch action {
	case "r":
		log.Printf("[ctl] rollback agent=%q", cgroupID)
		if err := shadowBackend.Rollback(cgroupID); err != nil {
			log.Printf("[ctl] rollback failed: %v", err)
			return 0, syscall.EIO
		}
	case "c":
		log.Printf("[ctl] commit agent=%q", cgroupID)
		shadowBackend.Commit(cgroupID)
	default:
		return 0, syscall.EINVAL
	}
	return uint32(len(data)), 0
}

// OnAdd installs the virtual .shadow.ctl file at the mount root.
func (n *OverlayNode) OnAdd(ctx context.Context) {
	if !n.IsRoot() {
		return
	}
	ch := n.NewPersistentInode(ctx, &controlFile{},
		fs.StableAttr{Mode: syscall.S_IFREG | 0o644})
	n.AddChild(ctlFileName, ch, true)
}

// --- cgroup id helper ---

// procStarttime returns field 22 of /proc/<pid>/stat (jiffies since
// boot at process creation) — invariant for a process's lifetime, used
// to disambiguate cached entries across pid reuse. Returns "" on error.
func procStarttime(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	// /proc/<pid>/stat format: "pid (comm) state ppid ...". The comm
	// field can contain spaces and parentheses, so locate the LAST ')'
	// then split the remainder.
	s := string(data)
	end := strings.LastIndex(s, ")")
	if end < 0 || end+2 >= len(s) {
		return ""
	}
	fields := strings.Fields(s[end+2:])
	// Index 19 in the post-comm slice corresponds to overall field 22.
	if len(fields) <= 19 {
		return ""
	}
	return fields[19]
}

// readCgroupRaw reads /proc/<pid>/cgroup with a small retry loop and
// returns the parsed cgroup path on success. Returns ("", err) if every
// attempt fails. Retries cover both transient empty reads (kernel
// mid-migration after systemd-run) and EBADF/EAGAIN-style read errors.
func readCgroupRaw(pid int) (string, error) {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	var data []byte
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		var err error
		data, err = os.ReadFile(cgroupPath)
		if err == nil && len(data) > 0 {
			lastErr = nil
			break
		}
		if err != nil {
			lastErr = err
		}
		time.Sleep(time.Duration(200*(attempt+1)) * time.Microsecond)
	}
	if lastErr != nil {
		return "", lastErr
	}
	if len(data) == 0 {
		return "", fmt.Errorf("empty cgroup file")
	}
	var v2Path, v1Path string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			v2Path = parts[2]
		case v1Path == "" && parts[2] != "" && parts[2] != "/":
			v1Path = parts[2]
		}
	}
	if v2Path != "" {
		return v2Path, nil
	}
	if v1Path != "" {
		return v1Path, nil
	}
	return "", fmt.Errorf("no usable cgroup path in %q", string(data))
}

// getCgroupID reads the cgroup ID of the calling process. Successful
// resolutions are cached by (pid, starttime) so that subsequent
// /proc/<pid>/cgroup read failures (observed as persistent EBADF on
// some kernels) fall back to the previously-known good answer instead
// of synthesising a bogus "pid-N" identifier that would split the
// process's operations across two distinct agent IDs.
func getCgroupID(ctx context.Context) string {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	pid := int(caller.Pid)
	start := procStarttime(pid)
	key := cgroupCacheKey{pid: pid, starttime: start}

	cgroup, err := readCgroupRaw(pid)
	if err == nil {
		if start != "" {
			cgroupCache.Store(key, cgroup)
		}
		return cgroup
	}
	// Read failed: prefer a cached value for the same (pid, starttime)
	// so a transient EBADF doesn't fragment the agent.
	if start != "" {
		if cached, ok := cgroupCache.Load(key); ok {
			return cached.(string)
		}
	}
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	log.Printf("[cgroup] read /proc/%d/cgroup failed: %v comm=%q (no cache hit, falling back to pid-N)",
		pid, err, strings.TrimSpace(string(comm)))
	return fmt.Sprintf("pid-%d", pid)
}

// --- Stat helpers ---

// resolveStat picks the effective stat for childPath: overlay (if visible)
// else orig. Returns (path used, stat, found).
func (r *OverlayRoot) resolveStat(rel string) (string, *syscall.Stat_t, bool) {
	origPath := filepath.Join(r.origDir, rel)
	overlayPath := filepath.Join(r.overlayDir, rel)

	whiteout := whiteoutPath(r.overlayDir, rel)
	if whiteout != "" {
		if _, err := os.Lstat(whiteout); err == nil {
			return "", nil, false
		}
	}
	// Check ancestor whiteouts: if any ancestor dir is deleted, this path is hidden.
	if hasAncestorWhiteout(r.overlayDir, rel) {
		return "", nil, false
	}

	var st syscall.Stat_t
	if err := syscall.Lstat(overlayPath, &st); err == nil {
		return overlayPath, &st, true
	}
	if err := syscall.Lstat(origPath, &st); err == nil {
		return origPath, &st, true
	}
	return "", nil, false
}

// whiteoutPath returns the whiteout marker path for rel, or "" if rel is
// the root itself.
func whiteoutPath(overlayDir, rel string) string {
	if rel == "" {
		return ""
	}
	dir, base := filepath.Split(rel)
	return filepath.Join(overlayDir, dir, ".shadow.wh."+base)
}

// hasAncestorWhiteout checks if any ancestor directory of rel has a whiteout marker.
func hasAncestorWhiteout(overlayDir, rel string) bool {
	dir := filepath.Dir(rel)
	for dir != "." && dir != "/" && dir != "" {
		wp := whiteoutPath(overlayDir, dir)
		if wp != "" {
			if _, err := os.Lstat(wp); err == nil {
				return true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

func attrFromStat(st *syscall.Stat_t, out *fuse.Attr) {
	out.Ino = st.Ino
	out.Size = uint64(st.Size)
	out.Blocks = uint64(st.Blocks)
	out.Atime = uint64(st.Atim.Sec)
	out.Atimensec = uint32(st.Atim.Nsec)
	out.Mtime = uint64(st.Mtim.Sec)
	out.Mtimensec = uint32(st.Mtim.Nsec)
	out.Ctime = uint64(st.Ctim.Sec)
	out.Ctimensec = uint32(st.Ctim.Nsec)
	out.Mode = st.Mode
	out.Nlink = uint32(st.Nlink)
	out.Owner = fuse.Owner{Uid: st.Uid, Gid: st.Gid}
	out.Rdev = uint32(st.Rdev)
	out.Blksize = uint32(st.Blksize)
}

// --- FUSE methods ---

func (n *OverlayNode) Getattr(ctx context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	rel := n.relPath()
	_, st, ok := n.root.resolveStat(rel)
	if !ok {
		return syscall.ENOENT
	}
	attrFromStat(st, &out.Attr)
	return 0
}

func (n *OverlayNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.IsRoot() && name == ctlFileName {
		if ch := n.GetChild(ctlFileName); ch != nil {
			out.Mode = syscall.S_IFREG | 0o644
			return ch, 0
		}
	}
	rel := filepath.Join(n.relPath(), name)
	_, st, ok := n.root.resolveStat(rel)
	if !ok {
		return nil, syscall.ENOENT
	}
	attrFromStat(st, &out.Attr)
	stable := fs.StableAttr{Mode: st.Mode & syscall.S_IFMT, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	return child, 0
}

// readdirEntry pairs a fuse.DirEntry with a sentinel for control file.
type sliceDirStream struct {
	entries []fuse.DirEntry
	idx     int
}

func (s *sliceDirStream) HasNext() bool { return s.idx < len(s.entries) }
func (s *sliceDirStream) Next() (fuse.DirEntry, syscall.Errno) {
	e := s.entries[s.idx]
	s.idx++
	return e, 0
}
func (s *sliceDirStream) Close() {}

func (n *OverlayNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	rel := n.relPath()
	// Check whiteout on the directory itself: if it was rmdir'd, a stale
	// cached inode should not list its contents.
	if wp := whiteoutPath(n.root.overlayDir, rel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return nil, syscall.ENOENT
		}
	}
	// Check ancestor whiteouts: if a parent dir is deleted, this dir is hidden.
	if rel != "" && hasAncestorWhiteout(n.root.overlayDir, rel) {
		return nil, syscall.ENOENT
	}

	cgroupID := getCgroupID(ctx)
	// Always record the read dependency, mirroring Open(R). Skipping it for
	// agents without active write state is unsafe: a purely-read agent may
	// later perform its first write to an unrelated path. At that moment
	// markDirty only links dependencies via fileDirty[origPath]/ancestors,
	// so any prior writers of paths the agent had merely *read* would be
	// missed and a cascaded rollback could fail to roll this agent back
	// even though its written content was derived from now-rolled-back data.
	shadowBackend.RecordReadOpen(cgroupID, n.origPath())
	origDir := filepath.Join(n.root.origDir, rel)
	overlayDir := filepath.Join(n.root.overlayDir, rel)

	merged, err := backend.MergeReaddir(origDir, overlayDir)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	entries := make([]fuse.DirEntry, 0, len(merged)+1)
	if n.IsRoot() {
		if ch := n.GetChild(ctlFileName); ch != nil {
			entries = append(entries, fuse.DirEntry{
				Name: ctlFileName,
				Mode: syscall.S_IFREG,
				Ino:  ch.StableAttr().Ino,
			})
		}
	}
	for _, e := range merged {
		entries = append(entries, fuse.DirEntry{
			Name: e.Name,
			Mode: uint32(e.Mode) & syscall.S_IFMT,
			Ino:  e.Ino,
		})
	}
	return &sliceDirStream{entries: entries}, 0
}

func (n *OverlayNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	rel := n.relPath()
	cgroupID := getCgroupID(ctx)
	isWrite := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0

	// Check whiteout: if the file is marked as deleted, reject the open
	// even if the kernel served a stale cached inode.
	if wp := whiteoutPath(n.root.overlayDir, rel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return nil, 0, syscall.ENOENT
		}
	}
	// Check ancestor whiteouts: a deleted parent hides this file.
	if hasAncestorWhiteout(n.root.overlayDir, rel) {
		return nil, 0, syscall.ENOENT
	}

	var openPath string
	onOverlay := false
	if isWrite {
		op, err := shadowBackend.PrepareWrite(cgroupID, n.origPath())
		if err != nil {
			log.Printf("[overlay] PrepareWrite failed: %v", err)
			return nil, 0, syscall.EIO
		}
		openPath = op
		onOverlay = true
	} else {
		shadowBackend.RecordReadOpen(cgroupID, n.origPath())
		// Read: prefer overlay if it has a copy.
		overlayPath := filepath.Join(n.root.overlayDir, rel)
		if _, err := os.Lstat(overlayPath); err == nil {
			openPath = overlayPath
			onOverlay = true
		} else {
			openPath = filepath.Join(n.root.origDir, rel)
		}
	}

	fd, err := syscall.Open(openPath, int(flags), 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	tfd := backend.NewTrackedFD(fd)
	shadowBackend.RegisterFD(cgroupID, tfd)
	return &trackedHandle{
		LoopbackFile: fs.NewLoopbackFile(fd).(*fs.LoopbackFile),
		tfd:          tfd,
		cgroupID:     cgroupID,
		onOverlay:    onOverlay,
	}, 0, 0
}

func (n *OverlayNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if n.IsRoot() && name == ctlFileName {
		ch := n.GetChild(ctlFileName)
		if ch != nil {
			fh, fuseFlags, errno := ch.Operations().(fs.NodeOpener).Open(ctx, flags)
			out.Mode = syscall.S_IFREG | 0o644
			return ch, fh, fuseFlags, errno
		}
	}
	cgroupID := getCgroupID(ctx)
	origChild := n.origChildPath(name)
	// Check ancestor whiteouts: reject create inside a deleted directory
	// even if the kernel served a stale cached inode for the parent.
	childRel := filepath.Join(n.relPath(), name)
	if hasAncestorWhiteout(n.root.overlayDir, childRel) {
		return nil, nil, 0, syscall.ENOENT
	}
	overlayPath, err := shadowBackend.PrepareWrite(cgroupID, origChild)
	if err != nil {
		log.Printf("[overlay] Create PrepareWrite failed: %v", err)
		return nil, nil, 0, syscall.EIO
	}

	fd, err := syscall.Open(overlayPath, int(flags)|syscall.O_CREAT, mode)
	if err != nil {
		return nil, nil, 0, fs.ToErrno(err)
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, nil, 0, fs.ToErrno(err)
	}
	attrFromStat(&st, &out.Attr)
	stable := fs.StableAttr{Mode: st.Mode & syscall.S_IFMT, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	tfd := backend.NewTrackedFD(fd)
	shadowBackend.RegisterFD(cgroupID, tfd)
	return child, &trackedHandle{
		LoopbackFile: fs.NewLoopbackFile(fd).(*fs.LoopbackFile),
		tfd:          tfd,
		cgroupID:     cgroupID,
		onOverlay:    true,
	}, 0, 0
}

func (n *OverlayNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cgroupID := getCgroupID(ctx)
	origChild := n.origChildPath(name)
	// Check ancestor whiteouts: reject mkdir inside a deleted directory.
	childRel := filepath.Join(n.relPath(), name)
	if hasAncestorWhiteout(n.root.overlayDir, childRel) {
		return nil, syscall.ENOENT
	}
	if err := shadowBackend.RecordMkdir(cgroupID, origChild, mode); err != nil {
		log.Printf("[overlay] RecordMkdir failed: %v", err)
		return nil, syscall.EIO
	}
	overlayChild := filepath.Join(n.root.overlayDir, n.relPath(), name)
	var st syscall.Stat_t
	if err := syscall.Lstat(overlayChild, &st); err != nil {
		return nil, fs.ToErrno(err)
	}
	attrFromStat(&st, &out.Attr)
	stable := fs.StableAttr{Mode: syscall.S_IFDIR, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	return child, 0
}

func (n *OverlayNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	cgroupID := getCgroupID(ctx)
	origChild := n.origChildPath(name)
	// Check whiteout: reject rmdir of an already-deleted path.
	childRel := filepath.Join(n.relPath(), name)
	if wp := whiteoutPath(n.root.overlayDir, childRel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return syscall.ENOENT
		}
	}
	if hasAncestorWhiteout(n.root.overlayDir, childRel) {
		return syscall.ENOENT
	}
	// POSIX rmdir must fail with ENOTEMPTY on non-empty directories.
	// We must check the merged view (orig + overlay minus whiteouts), not
	// just the overlay copy: the agent may not have copy-up'd yet, but the
	// orig dir still has children visible through the merged view.
	// Re-check whiteout on the child itself AND ancestors before reading:
	// another agent may have deleted this dir or a parent while the kernel
	// held a stale cached inode, and MergeReaddir does not consider
	// ancestor whiteouts — it would return orig children and incorrectly
	// trigger ENOTEMPTY instead of the correct ENOENT.
	if wp := whiteoutPath(n.root.overlayDir, childRel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return syscall.ENOENT
		}
	}
	if hasAncestorWhiteout(n.root.overlayDir, childRel) {
		return syscall.ENOENT
	}
	origChildAbs := filepath.Join(n.root.origDir, childRel)
	overlayChildAbs := filepath.Join(n.root.overlayDir, childRel)
	if merged, err := backend.MergeReaddir(origChildAbs, overlayChildAbs); err == nil && len(merged) > 0 {
		return syscall.ENOTEMPTY
	}
	if err := shadowBackend.RecordRmdir(cgroupID, origChild); err != nil {
		log.Printf("[overlay] RecordRmdir failed: %v", err)
		return syscall.EIO
	}
	return 0
}

func (n *OverlayNode) Unlink(ctx context.Context, name string) syscall.Errno {
	cgroupID := getCgroupID(ctx)
	origChild := n.origChildPath(name)
	// Check whiteout: reject unlink of an already-deleted path.
	childRel := filepath.Join(n.relPath(), name)
	if wp := whiteoutPath(n.root.overlayDir, childRel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return syscall.ENOENT
		}
	}
	if hasAncestorWhiteout(n.root.overlayDir, childRel) {
		return syscall.ENOENT
	}
	if err := shadowBackend.RecordUnlink(cgroupID, origChild); err != nil {
		log.Printf("[overlay] RecordUnlink failed: %v", err)
		return syscall.EIO
	}
	return 0
}

func (n *OverlayNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	cgroupID := getCgroupID(ctx)
	oldOrig := n.origChildPath(name)
	newParentNode, ok := newParent.(*OverlayNode)
	if !ok {
		return syscall.EINVAL
	}
	newOrig := newParentNode.origChildPath(newName)

	// Whiteout checks on source path: reject rename of a deleted file
	// even if the kernel served a stale cached inode.
	oldRel := filepath.Join(n.relPath(), name)
	if wp := whiteoutPath(n.root.overlayDir, oldRel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return syscall.ENOENT
		}
	}
	if hasAncestorWhiteout(n.root.overlayDir, oldRel) {
		return syscall.ENOENT
	}

	// Whiteout checks on destination: reject rename into a deleted path
	// (direct whiteout) or into a deleted directory (ancestor whiteout).
	newRel := filepath.Join(newParentNode.relPath(), newName)
	if wp := whiteoutPath(n.root.overlayDir, newRel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return syscall.ENOENT
		}
	}
	if hasAncestorWhiteout(n.root.overlayDir, newRel) {
		return syscall.ENOENT
	}

	// POSIX rename type/emptiness validation. Without this the overlay
	// rename would happen, but a later promote would call os.Rename on
	// orig and fail with EISDIR / ENOTDIR / ENOTEMPTY — leaving the agent
	// permanently un-finalisable. Validate against the merged view that
	// the user actually sees.
	// Re-check whiteouts before reading merged state: another agent may
	// have deleted the source or destination while the kernel held stale
	// cached inodes, and MergeReaddir does not consider ancestor whiteouts.
	if wp := whiteoutPath(n.root.overlayDir, oldRel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return syscall.ENOENT
		}
	}
	if hasAncestorWhiteout(n.root.overlayDir, oldRel) {
		return syscall.ENOENT
	}
	if wp := whiteoutPath(n.root.overlayDir, newRel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return syscall.ENOENT
		}
	}
	if hasAncestorWhiteout(n.root.overlayDir, newRel) {
		return syscall.ENOENT
	}
	_, srcSt, srcExists := n.root.resolveStat(oldRel)
	if !srcExists {
		return syscall.ENOENT
	}
	if _, dstSt, dstExists := n.root.resolveStat(newRel); dstExists {
		srcIsDir := (srcSt.Mode & syscall.S_IFMT) == syscall.S_IFDIR
		dstIsDir := (dstSt.Mode & syscall.S_IFMT) == syscall.S_IFDIR
		switch {
		case srcIsDir && !dstIsDir:
			return syscall.ENOTDIR
		case !srcIsDir && dstIsDir:
			return syscall.EISDIR
		case srcIsDir && dstIsDir:
			// POSIX: dst dir must be empty.
			dstOrigAbs := filepath.Join(n.root.origDir, newRel)
			dstOverlayAbs := filepath.Join(n.root.overlayDir, newRel)
			if merged, err := backend.MergeReaddir(dstOrigAbs, dstOverlayAbs); err == nil && len(merged) > 0 {
				return syscall.ENOTEMPTY
			}
		}
	}

	if err := shadowBackend.RecordRename(cgroupID, oldOrig, newOrig); err != nil {
		log.Printf("[overlay] RecordRename failed: %v", err)
		return fs.ToErrno(err)
	}
	return 0
}

// Setattr handles chmod/chown/truncate/utimes by routing to the overlay
// copy. Truncation triggers a copy-up so the orig file is never resized.
func (n *OverlayNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	rel := n.relPath()
	if rel == "" {
		// Root: nothing meaningful to update on the orig side.
		return n.Getattr(ctx, fh, out)
	}

	// Check whiteout FIRST, before any attribute modification. This
	// ensures consistent behaviour whether the call arrives via an open
	// file handle or a path-based lookup, and prevents stale cached
	// inodes from modifying already-deleted files.
	if wp := whiteoutPath(n.root.overlayDir, rel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return syscall.ENOENT
		}
	}
	if hasAncestorWhiteout(n.root.overlayDir, rel) {
		return syscall.ENOENT
	}

	if th, ok := fh.(*trackedHandle); ok && th.onOverlay {
		// Fast path: the fd is known to point at an overlay copy, so
		// applying chmod / chown / truncate / utimens via the fd is
		// safe and avoids re-running PrepareWrite.
		if sa, ok := fh.(fs.FileSetattrer); ok {
			if errno := sa.Setattr(ctx, in, out); errno != 0 {
				return errno
			}
			return n.Getattr(ctx, fh, out)
		}
	}
	// Either fh is nil, fh is a non-trackedHandle, or fh's fd points
	// directly at the orig file (R-only open with no overlay copy at
	// open time). In those cases delegating to fh.Setattr would mutate
	// the orig file (e.g. fchmod / fchown / futimens do not require a
	// writable fd) — violating the "orig is immutable" invariant and
	// leaving no UndoLog entry. Force the path-based route so that
	// PrepareWrite materialises an overlay copy and records the
	// attribute change for rollback.

	cgroupID := getCgroupID(ctx)
	overlayPath, err := shadowBackend.PrepareWrite(cgroupID, n.origPath())
	if err != nil {
		return syscall.EIO
	}

	if size, ok := in.GetSize(); ok {
		if err := os.Truncate(overlayPath, int64(size)); err != nil {
			return fs.ToErrno(err)
		}
	}
	if mode, ok := in.GetMode(); ok {
		if err := os.Chmod(overlayPath, os.FileMode(mode)); err != nil {
			return fs.ToErrno(err)
		}
	}
	if uid, uok := in.GetUID(); uok {
		gid, _ := in.GetGID()
		if err := os.Chown(overlayPath, int(uid), int(gid)); err != nil {
			return fs.ToErrno(err)
		}
	} else if gid, gok := in.GetGID(); gok {
		if err := os.Chown(overlayPath, -1, int(gid)); err != nil {
			return fs.ToErrno(err)
		}
	}
	// Time updates: each of atime/mtime can be (a) a specific value
	// (FATTR_ATIME / FATTR_MTIME), (b) "now" (FATTR_ATIME_NOW /
	// FATTR_MTIME_NOW), or (c) untouched. Untouched fields must keep their
	// existing on-disk value, so when only one of the two is set we must
	// read the other from the overlay file rather than passing zero.
	atimeSet := in.Valid&(fuse.FATTR_ATIME|fuse.FATTR_ATIME_NOW) != 0
	mtimeSet := in.Valid&(fuse.FATTR_MTIME|fuse.FATTR_MTIME_NOW) != 0
	if atimeSet || mtimeSet {
		now := time.Now()
		var curATime, curMTime time.Time
		if !(atimeSet && mtimeSet) {
			if st, err := os.Stat(overlayPath); err == nil {
				curMTime = st.ModTime()
				if sysStat, ok := st.Sys().(*syscall.Stat_t); ok {
					curATime = time.Unix(sysStat.Atim.Sec, sysStat.Atim.Nsec)
				} else {
					curATime = curMTime
				}
			}
		}
		var atime, mtime time.Time
		switch {
		case in.Valid&fuse.FATTR_ATIME_NOW != 0:
			atime = now
		case in.Valid&fuse.FATTR_ATIME != 0:
			atime, _ = in.GetATime()
		default:
			atime = curATime
		}
		switch {
		case in.Valid&fuse.FATTR_MTIME_NOW != 0:
			mtime = now
		case in.Valid&fuse.FATTR_MTIME != 0:
			mtime, _ = in.GetMTime()
		default:
			mtime = curMTime
		}
		if err := os.Chtimes(overlayPath, atime, mtime); err != nil {
			return fs.ToErrno(err)
		}
	}

	return n.Getattr(ctx, fh, out)
}

// Readlink resolves a symlink either from overlay or orig.
func (n *OverlayNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	rel := n.relPath()
	// Check whiteout: stale cached inode should not resolve a deleted symlink.
	if wp := whiteoutPath(n.root.overlayDir, rel); wp != "" {
		if _, err := os.Lstat(wp); err == nil {
			return nil, syscall.ENOENT
		}
	}
	// Check ancestor whiteouts: a deleted parent hides this symlink.
	if hasAncestorWhiteout(n.root.overlayDir, rel) {
		return nil, syscall.ENOENT
	}
	// Overlay takes precedence: if overlay exists at this path it represents
	// the agent-visible state. If it is NOT a symlink (e.g. the path was
	// replaced by a regular file), we must NOT silently fall back to orig's
	// stale symlink — return EINVAL like the kernel does for readlink on a
	// non-symlink.
	overlayPath := filepath.Join(n.root.overlayDir, rel)
	if st, err := os.Lstat(overlayPath); err == nil {
		if st.Mode()&os.ModeSymlink == 0 {
			return nil, syscall.EINVAL
		}
		target, err := os.Readlink(overlayPath)
		if err != nil {
			return nil, fs.ToErrno(err)
		}
		return []byte(target), 0
	}
	target, err := os.Readlink(filepath.Join(n.root.origDir, rel))
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return []byte(target), 0
}

// --- main ---

func main() {
	log.SetFlags(log.Lmicroseconds)
	debug := flag.Bool("debug", false, "print debugging messages.")
	staging := flag.String("staging", "", "staging directory for overlay (required)")
	sockPath := flag.String("sock", "", "Unix socket path for control API (optional)")
	allowOther := flag.Bool("allow-other", false, "allow other users to access the mount")
	flag.Parse()
	if flag.NArg() < 2 || *staging == "" {
		fmt.Printf("usage: %s -staging STAGING_DIR [-sock SOCKET_PATH] MOUNTPOINT ORIGINAL\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(2)
	}

	mntDir := flag.Arg(0)
	origDir := flag.Arg(1)
	stagingDir := *staging

	var err error
	shadowBackend, err = backend.NewBackend(stagingDir, origDir)
	if err != nil {
		log.Fatalf("NewBackend: %v", err)
	}

	root := &OverlayNode{
		root: &OverlayRoot{
			origDir:    origDir,
			overlayDir: shadowBackend.OverlayDir(),
		},
	}

	sec := time.Second
	opts := &fs.Options{
		AttrTimeout:  &sec,
		EntryTimeout: &sec,
		MountOptions: fuse.MountOptions{
			Debug:             *debug,
			AllowOther:        *allowOther,
			ExtraCapabilities: fuse.CAP_ATOMIC_O_TRUNC,
		},
	}
	server, err := fs.Mount(mntDir, root, opts)
	if err != nil {
		log.Fatalf("Mount fail: %v\n", err)
	}
	fmt.Printf("Mounted! orig=%q overlay=%q\n", origDir, shadowBackend.OverlayDir())

	// Start Unix socket control server if requested
	var sockServer *SocketServer
	if *sockPath != "" {
		var err error
		sockServer, err = NewSocketServer(*sockPath)
		if err != nil {
			log.Fatalf("Socket server: %v", err)
		}
		fmt.Printf("Control socket: %s\n", *sockPath)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[main] received signal, unmounting...")
		server.Unmount()
	}()

	server.Wait()
	if sockServer != nil {
		sockServer.Close()
	}
	shadowBackend.Close()
}
