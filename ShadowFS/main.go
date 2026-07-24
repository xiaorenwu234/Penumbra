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
	"golang.org/x/sys/unix"

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
	_ fs.NodeLookuper      = (*OverlayNode)(nil)
	_ fs.NodeGetattrer     = (*OverlayNode)(nil)
	_ fs.NodeReaddirer     = (*OverlayNode)(nil)
	_ fs.NodeOpener        = (*OverlayNode)(nil)
	_ fs.NodeCreater       = (*OverlayNode)(nil)
	_ fs.NodeMkdirer       = (*OverlayNode)(nil)
	_ fs.NodeRmdirer       = (*OverlayNode)(nil)
	_ fs.NodeUnlinker      = (*OverlayNode)(nil)
	_ fs.NodeRenamer       = (*OverlayNode)(nil)
	_ fs.NodeSetattrer     = (*OverlayNode)(nil)
	_ fs.NodeReadlinker    = (*OverlayNode)(nil)
	_ fs.NodeLinker        = (*OverlayNode)(nil)
	_ fs.NodeMknoder       = (*OverlayNode)(nil)
	_ fs.NodeGetxattrer    = (*OverlayNode)(nil)
	_ fs.NodeSetxattrer    = (*OverlayNode)(nil)
	_ fs.NodeRemovexattrer = (*OverlayNode)(nil)
	_ fs.NodeListxattrer   = (*OverlayNode)(nil)
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

// Advisory file locks pass through to the underlying overlay/orig fd: the
// embedded *fs.LoopbackFile already implements the lock operations, so these
// assertions simply confirm trackedHandle exposes them. Both POSIX (fcntl)
// and BSD (flock) locks arrive via Setlk/Setlkw (flock carries a LOCK_* flag),
// so there is no separate Flock interface. Locks are ephemeral process state
// (per the design): a rollback force-closes the agent's fds (CloseAgentFDs),
// which releases any locks it held; no lock state is recorded in the undo log.
var (
	_ fs.FileGetlker  = (*trackedHandle)(nil)
	_ fs.FileSetlker  = (*trackedHandle)(nil)
	_ fs.FileSetlkwer = (*trackedHandle)(nil)
)

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
//
// The in-mount virtual control file (.shadow.ctl) has been REMOVED: it exposed
// rollback/commit to any process that could write into the mount (i.e. the
// sandboxed agent itself), letting the agent drive its own finalization. The
// only control interface is now the ShadowFS Unix control socket
// (socket_server.go), which is not reachable through the filesystem view and
// is peer-authenticated to the orchestrator's uid.

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
		// Copy-up on any writable open. A writable MAP_SHARED mapping requires
		// an O_RDWR fd, so its page writeback flows through this overlay fd and
		// is captured + marked dirty here (mmap write tracking). MAP_PRIVATE
		// mappings never reach the file and need no tracking. NOTE: dirty pages
		// of a still-live MAP_SHARED mapping that a frozen process has not yet
		// written back are outside the rollback/commit guarantee until full
		// mapping pin + writeback quiescence is implemented; flushAgentFDs at
		// commit captures already-written-back pages.
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

// xattrReadPath returns the path to read xattrs from: the overlay copy when
// one exists (so an agent sees its own copy-up + modifications), else orig.
func (n *OverlayNode) xattrReadPath() string {
	rel := n.relPath()
	op := filepath.Join(n.root.overlayDir, rel)
	if _, err := os.Lstat(op); err == nil {
		return op
	}
	return filepath.Join(n.root.origDir, rel)
}

// Link creates a hard link `name` in this directory pointing at `target`,
// tracked speculatively (see backend.RecordLink). On commit the link is
// promoted as a real hard link on the orig FS; on rollback it is discarded.
func (n *OverlayNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cgroupID := getCgroupID(ctx)
	tgt, ok := target.(*OverlayNode)
	if !ok {
		return nil, syscall.EXDEV
	}
	targetOrig := tgt.origPath()
	linkOrig := n.origChildPath(name)

	childRel := filepath.Join(n.relPath(), name)
	if hasAncestorWhiteout(n.root.overlayDir, childRel) {
		return nil, syscall.ENOENT
	}
	if err := shadowBackend.RecordLink(cgroupID, targetOrig, linkOrig); err != nil {
		log.Printf("[overlay] RecordLink failed: %v", err)
		return nil, fs.ToErrno(err)
	}
	// Stat the overlay link to fill the entry (Nlink reflects the shared inode).
	overlayLink := filepath.Join(n.root.overlayDir, childRel)
	var st syscall.Stat_t
	if err := syscall.Lstat(overlayLink, &st); err != nil {
		return nil, fs.ToErrno(err)
	}
	attrFromStat(&st, &out.Attr)
	stable := fs.StableAttr{Mode: st.Mode & syscall.S_IFMT, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	return child, 0
}

// Mknod creates a special file (FIFO / socket / char / block device) `name`
// in this directory, tracked speculatively (see backend.RecordMknod).
func (n *OverlayNode) Mknod(ctx context.Context, name string, mode uint32, rdev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cgroupID := getCgroupID(ctx)
	origChild := n.origChildPath(name)
	childRel := filepath.Join(n.relPath(), name)
	if hasAncestorWhiteout(n.root.overlayDir, childRel) {
		return nil, syscall.ENOENT
	}
	if err := shadowBackend.RecordMknod(cgroupID, origChild, mode, uint64(rdev)); err != nil {
		log.Printf("[overlay] RecordMknod failed: %v", err)
		return nil, fs.ToErrno(err)
	}
	overlayChild := filepath.Join(n.root.overlayDir, childRel)
	var st syscall.Stat_t
	if err := syscall.Lstat(overlayChild, &st); err != nil {
		return nil, fs.ToErrno(err)
	}
	attrFromStat(&st, &out.Attr)
	stable := fs.StableAttr{Mode: st.Mode & syscall.S_IFMT, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	return child, 0
}

// Getxattr reads one extended attribute (incl. ACLs, which are xattrs) from
// the agent's current view (overlay copy if present, else orig).
func (n *OverlayNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	sz, err := syscall.Getxattr(n.xattrReadPath(), attr, dest)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	return uint32(sz), 0
}

// Listxattr lists extended attribute names from the agent's current view.
func (n *OverlayNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	sz, err := syscall.Listxattr(n.xattrReadPath(), dest)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	return uint32(sz), 0
}

// Setxattr sets an extended attribute (incl. ACLs). It first copies the file
// up (RecordXattrWrite tracks it as a speculative write) so the change lands
// on the overlay copy; commit's promote rename carries the modified xattrs,
// and rollback discards the overlay copy leaving orig xattrs intact.
func (n *OverlayNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	cgroupID := getCgroupID(ctx)
	overlayPath, err := shadowBackend.RecordXattrWrite(cgroupID, n.origPath())
	if err != nil {
		log.Printf("[overlay] Setxattr copy-up failed: %v", err)
		return fs.ToErrno(err)
	}
	if err := syscall.Setxattr(overlayPath, attr, data, int(flags)); err != nil {
		return fs.ToErrno(err)
	}
	return 0
}

// Removexattr removes an extended attribute, tracked like Setxattr.
func (n *OverlayNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	cgroupID := getCgroupID(ctx)
	overlayPath, err := shadowBackend.RecordXattrWrite(cgroupID, n.origPath())
	if err != nil {
		log.Printf("[overlay] Removexattr copy-up failed: %v", err)
		return fs.ToErrno(err)
	}
	if err := syscall.Removexattr(overlayPath, attr); err != nil {
		return fs.ToErrno(err)
	}
	return 0
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

	// Whiteout checks on destination: renaming INTO a directly-whiteout'd
	// path is LEGAL — it overwrites a name another agent deleted. We must NOT
	// reject on a direct destination whiteout; RecordRename clears it and
	// records dstHadWh so a rollback restores it. Only reject when an ANCESTOR
	// directory is deleted (the destination location itself is gone).
	newRel := filepath.Join(newParentNode.relPath(), newName)
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
	// (No direct destination-whiteout reject here either: renaming over a
	// whiteout'd name is a legal overwrite — see above.)
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

	// Harden the control plane (issue #2): forbid gaining privileges via a
	// setuid/setgid bit. Enabled only when already root: FUSE (un)mount shells
	// out to the setuid-root `fusermount3`, which a NON-root daemon relies on to
	// elevate -- no_new_privs would break that. A root daemon never needs to
	// elevate, so enabling it there is safe and is inherited by any child.
	if os.Geteuid() == 0 {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			log.Printf("[main] Warning: PR_SET_NO_NEW_PRIVS failed: %v -- continuing", err)
		}
	}

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
			// Enable POSIX (fcntl) and BSD (flock) advisory file locking so
			// the trackedHandle lock passthrough (Getlk/Setlk/Setlkw/Flock)
			// is exercised by the kernel.
			EnableLocks: true,
		},
	}
	server, err := fs.Mount(mntDir, root, opts)
	if err != nil {
		log.Fatalf("Mount fail: %v\n", err)
	}
	fmt.Printf("Mounted! orig=%q overlay=%q\n", origDir, shadowBackend.OverlayDir())

	// Rollback removes overlay files out-of-band (via the control socket, not
	// through the FUSE data path), so the kernel's dentry cache (EntryTimeout)
	// keeps serving stale positive entries for paths whose overlay copy was
	// just deleted — most visibly the destination of a rolled-back rename.
	// Invalidate those entries so the next lookup re-resolves the merged view.
	rootInode := root.EmbeddedInode()
	shadowBackend.SetInvalidateCallback(func(paths []string) {
		for _, p := range paths {
			rel, err := filepath.Rel(origDir, p)
			if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			parts := strings.Split(rel, string(os.PathSeparator))
			parent := rootInode
			ok := true
			for _, comp := range parts[:len(parts)-1] {
				child := parent.GetChild(comp)
				if child == nil {
					ok = false // ancestor not cached → nothing stale below it
					break
				}
				parent = child
			}
			if ok {
				parent.NotifyEntry(parts[len(parts)-1])
			}
		}
	})

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
