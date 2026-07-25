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

// shadowBackend is the global MVCC backend, initialized in main.
var shadowBackend *backend.Backend

// OverlayRoot is the shared state of the versioned mount: orig (read-only
// source of truth) plus the backend that owns version resolution and
// rollback/commit semantics. There is NO shared overlay directory anymore:
// each epoch has a private stage tree and visibility is decided by the
// backend's version graph (Resolve).
type OverlayRoot struct {
	origDir string
}

// OverlayNode is a single inode in the merged versioned view.
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
// (CloseEpochFDs) or by the kernel's RELEASE, whichever comes first.
//
// onStage records whether the embedded fd points at the epoch's stage
// copy (true) or directly at the backing file (false). Setattr uses this
// to decide whether the fast-path fh.Setattr is safe: applying chmod /
// chown / utimens / truncate via a backing-bound fd would mutate the
// supposedly-immutable orig file and bypass PrepareWrite entirely.
type trackedHandle struct {
	*fs.LoopbackFile
	tfd     *backend.TrackedFD
	epochID backend.EpochID
	onStage bool
}

var _ fs.FileReleaser = (*trackedHandle)(nil)

// Advisory file locks pass through to the underlying stage/orig fd: the
// embedded *fs.LoopbackFile already implements the lock operations. Locks
// are ephemeral process state: a rollback force-closes the epoch's fds
// (CloseEpochFDs), which releases any locks it held; no lock state is
// recorded in the version graph.
var (
	_ fs.FileGetlker  = (*trackedHandle)(nil)
	_ fs.FileSetlker  = (*trackedHandle)(nil)
	_ fs.FileSetlkwer = (*trackedHandle)(nil)
)

func (h *trackedHandle) Release(ctx context.Context) syscall.Errno {
	// Unregister from backend so CloseEpochFDs won't double-close.
	shadowBackend.UnregisterFD(h.epochID, h.tfd)
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
// some kernels) fall back to the previously-known good answer.
//
// Fail-closed policy: if the cgroup path cannot be resolved AND there is
// no cached value, the function returns an error. The caller (epochForCtx)
// translates this into an EIO on the FUSE operation, refusing the request.
// This prevents a synthetic "pid-N" identifier from fragmenting the
// process's operations across two distinct identities — which would break
// commit/rollback grouping and dependency tracking.
func getCgroupID(ctx context.Context) (string, error) {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no caller pid in FUSE context")
	}
	pid := int(caller.Pid)
	start := procStarttime(pid)
	key := cgroupCacheKey{pid: pid, starttime: start}

	cgroup, err := readCgroupRaw(pid)
	if err == nil {
		if start != "" {
			cgroupCache.Store(key, cgroup)
		}
		return cgroup, nil
	}
	// Read failed: prefer a cached value for the same (pid, starttime)
	// so a transient EBADF doesn't fragment the identity.
	if start != "" {
		if cached, ok := cgroupCache.Load(key); ok {
			return cached.(string), nil
		}
	}
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return "", fmt.Errorf("cgroup read failed for pid %d (comm=%q): %w — no cache hit, refusing synthetic identity (fail-closed)",
		pid, strings.TrimSpace(string(comm)), err)
}

// epochForCtx maps the calling process to the epoch its operations are
// attributed to: the cgroup's registered active epoch, or an auto-created
// implicit epoch for cgroup-only legacy flows.
//
// Fail-closed: if cgroup identification fails (no path, no cache), the
// FUSE operation returns EIO instead of attributing the write to a
// synthetic identity.
func epochForCtx(ctx context.Context) (backend.EpochID, syscall.Errno) {
	cgID, err := getCgroupID(ctx)
	if err != nil {
		log.Printf("[overlay] cgroup identification failed (fail-closed): %v", err)
		return "", syscall.EIO
	}
	epochID, err := shadowBackend.EpochForCgroup(cgID)
	if err != nil {
		log.Printf("[overlay] epoch attribution failed: %v", err)
		return "", syscall.EIO
	}
	return epochID, 0
}

// --- Stat helpers ---

// resolveStat resolves rel in the caller's epoch view and stats the
// resolved physical path. Returns (physical path, stat, found). Recording of
// the read-from dependency happens inside backend.Resolve.
func (n *OverlayNode) resolveStat(epochID backend.EpochID, rel string) (string, *syscall.Stat_t, bool) {
	res := shadowBackend.Resolve(epochID, filepath.Join(n.root.origDir, rel))
	if !res.Exists {
		return "", nil, false
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(res.PhysicalPath, &st); err != nil {
		return "", nil, false
	}
	return res.PhysicalPath, &st, true
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
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return errno
	}
	_, st, ok := n.resolveStat(epochID, n.relPath())
	if !ok {
		return syscall.ENOENT
	}
	attrFromStat(st, &out.Attr)
	return 0
}

func (n *OverlayNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return nil, errno
	}
	rel := filepath.Join(n.relPath(), name)
	_, st, ok := n.resolveStat(epochID, rel)
	if !ok {
		return nil, syscall.ENOENT
	}
	attrFromStat(st, &out.Attr)
	stable := fs.StableAttr{Mode: st.Mode & syscall.S_IFMT, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	return child, 0
}

// sliceDirStream serves a pre-merged directory listing.
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
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return nil, errno
	}
	rel := n.relPath()
	// Resolve the directory itself: a whiteout (own or ancestor) hides it
	// even when the kernel served a stale cached inode.
	if rel != "" {
		res := shadowBackend.Resolve(epochID, n.origPath())
		if !res.Exists {
			return nil, syscall.ENOENT
		}
	}
	// MergeReaddirVersions records a read-from edge for every foreign
	// version the enumeration observes (directory namespace reads).
	merged, err := shadowBackend.MergeReaddirVersions(epochID, n.origPath())
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	entries := make([]fuse.DirEntry, 0, len(merged))
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
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return nil, 0, errno
	}
	isWrite := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0

	var openPath string
	onStage := false
	if isWrite {
		// Version-on-write: any writable open creates (or reuses) the
		// epoch's own version. A writable MAP_SHARED mapping requires an
		// O_RDWR fd, so its page writeback flows through this stage fd and
		// is captured here (mmap write tracking). NOTE: dirty pages of a
		// still-live MAP_SHARED mapping that a frozen process has not yet
		// written back are captured by quiesceMappings at commit time.
		res := shadowBackend.Resolve(epochID, n.origPath())
		if !res.Exists {
			return nil, 0, syscall.ENOENT
		}
		sp, err := shadowBackend.PrepareWrite(epochID, n.origPath())
		if err != nil {
			log.Printf("[overlay] PrepareWrite failed: %v", err)
			return nil, 0, fs.ToErrno(err)
		}
		openPath = sp
		onStage = true
	} else {
		// Read: resolve the epoch's view; Resolve records the read-from
		// edge on the actually-observed version.
		res := shadowBackend.Resolve(epochID, n.origPath())
		if !res.Exists {
			return nil, 0, syscall.ENOENT
		}
		openPath = res.PhysicalPath
		onStage = res.Version != 0
	}

	fd, err := syscall.Open(openPath, int(flags), 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	tfd := backend.NewTrackedFD(fd)
	shadowBackend.RegisterFD(epochID, tfd)
	return &trackedHandle{
		LoopbackFile: fs.NewLoopbackFile(fd).(*fs.LoopbackFile),
		tfd:          tfd,
		epochID:      epochID,
		onStage:      onStage,
	}, 0, 0
}

func (n *OverlayNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	origChild := n.origChildPath(name)
	// Reject create inside a deleted directory even if the kernel served a
	// stale cached inode for the parent (ancestor whiteout check happens
	// inside Resolve on the PARENT path).
	if parentRes := shadowBackend.Resolve(epochID, n.origPath()); n.relPath() != "" && !parentRes.Exists {
		return nil, nil, 0, syscall.ENOENT
	}
	stagePath, err := shadowBackend.PrepareCreate(epochID, origChild)
	if err != nil {
		log.Printf("[overlay] Create PrepareWrite failed: %v", err)
		return nil, nil, 0, fs.ToErrno(err)
	}

	fd, err := syscall.Open(stagePath, int(flags)|syscall.O_CREAT, mode)
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
	shadowBackend.RegisterFD(epochID, tfd)
	return child, &trackedHandle{
		LoopbackFile: fs.NewLoopbackFile(fd).(*fs.LoopbackFile),
		tfd:          tfd,
		epochID:      epochID,
		onStage:      true,
	}, 0, 0
}

// xattrReadPath resolves the path xattrs are read from: the epoch's view of
// the file (its own or the visible version, else backing).
func (n *OverlayNode) xattrReadPath(epochID backend.EpochID) (string, syscall.Errno) {
	res := shadowBackend.Resolve(epochID, n.origPath())
	if !res.Exists {
		return "", syscall.ENOENT
	}
	return res.PhysicalPath, 0
}

// Link creates a hard link `name` in this directory pointing at `target`,
// tracked as an OpLink version (see backend.RecordLink). On promotion the
// link is recreated as a real hard link on the backing FS; on rollback it is
// discarded.
func (n *OverlayNode) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return nil, errno
	}
	tgt, ok := target.(*OverlayNode)
	if !ok {
		return nil, syscall.EXDEV
	}
	targetOrig := tgt.origPath()
	linkOrig := n.origChildPath(name)

	if parentRes := shadowBackend.Resolve(epochID, n.origPath()); n.relPath() != "" && !parentRes.Exists {
		return nil, syscall.ENOENT
	}
	stagePath, err := shadowBackend.RecordLink(epochID, targetOrig, linkOrig)
	if err != nil {
		log.Printf("[overlay] RecordLink failed: %v", err)
		return nil, fs.ToErrno(err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(stagePath, &st); err != nil {
		return nil, fs.ToErrno(err)
	}
	attrFromStat(&st, &out.Attr)
	stable := fs.StableAttr{Mode: st.Mode & syscall.S_IFMT, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	return child, 0
}

// Mknod creates a special file (FIFO / socket / char / block device) `name`
// in this directory, tracked as an OpMknod version.
func (n *OverlayNode) Mknod(ctx context.Context, name string, mode uint32, rdev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return nil, errno
	}
	origChild := n.origChildPath(name)
	if parentRes := shadowBackend.Resolve(epochID, n.origPath()); n.relPath() != "" && !parentRes.Exists {
		return nil, syscall.ENOENT
	}
	if err := shadowBackend.RecordMknod(epochID, origChild, mode, uint64(rdev)); err != nil {
		log.Printf("[overlay] RecordMknod failed: %v", err)
		return nil, fs.ToErrno(err)
	}
	res := shadowBackend.Resolve(epochID, origChild)
	if !res.Exists {
		return nil, syscall.EIO
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(res.PhysicalPath, &st); err != nil {
		return nil, fs.ToErrno(err)
	}
	attrFromStat(&st, &out.Attr)
	stable := fs.StableAttr{Mode: st.Mode & syscall.S_IFMT, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	return child, 0
}

// Getxattr reads one extended attribute (incl. ACLs, which are xattrs) from
// the epoch's current view.
func (n *OverlayNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return 0, errno
	}
	p, errno := n.xattrReadPath(epochID)
	if errno != 0 {
		return 0, errno
	}
	sz, err := syscall.Getxattr(p, attr, dest)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	return uint32(sz), 0
}

// Listxattr lists extended attribute names from the epoch's current view.
func (n *OverlayNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return 0, errno
	}
	p, errno := n.xattrReadPath(epochID)
	if errno != 0 {
		return 0, errno
	}
	sz, err := syscall.Listxattr(p, dest)
	if err != nil {
		return 0, fs.ToErrno(err)
	}
	return uint32(sz), 0
}

// Setxattr sets an extended attribute (incl. ACLs). It first copies the file
// up into the epoch's stage tree (RecordXattrWrite versions it) so the
// change lands on the epoch's own copy; promotion carries the modified
// xattrs, rollback discards them leaving the backing xattrs intact.
func (n *OverlayNode) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return errno
	}
	stagePath, err := shadowBackend.RecordXattrWrite(epochID, n.origPath())
	if err != nil {
		log.Printf("[overlay] Setxattr copy-up failed: %v", err)
		return fs.ToErrno(err)
	}
	if err := syscall.Setxattr(stagePath, attr, data, int(flags)); err != nil {
		return fs.ToErrno(err)
	}
	return 0
}

// Removexattr removes an extended attribute, tracked like Setxattr.
func (n *OverlayNode) Removexattr(ctx context.Context, attr string) syscall.Errno {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return errno
	}
	stagePath, err := shadowBackend.RecordXattrWrite(epochID, n.origPath())
	if err != nil {
		log.Printf("[overlay] Removexattr copy-up failed: %v", err)
		return fs.ToErrno(err)
	}
	if err := syscall.Removexattr(stagePath, attr); err != nil {
		return fs.ToErrno(err)
	}
	return 0
}

func (n *OverlayNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return nil, errno
	}
	origChild := n.origChildPath(name)
	if parentRes := shadowBackend.Resolve(epochID, n.origPath()); n.relPath() != "" && !parentRes.Exists {
		return nil, syscall.ENOENT
	}
	if err := shadowBackend.RecordMkdir(epochID, origChild, mode); err != nil {
		log.Printf("[overlay] RecordMkdir failed: %v", err)
		return nil, syscall.EIO
	}
	res := shadowBackend.Resolve(epochID, origChild)
	if !res.Exists {
		return nil, syscall.EIO
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(res.PhysicalPath, &st); err != nil {
		return nil, fs.ToErrno(err)
	}
	attrFromStat(&st, &out.Attr)
	stable := fs.StableAttr{Mode: syscall.S_IFDIR, Ino: st.Ino}
	child := n.NewInode(ctx, &OverlayNode{root: n.root}, stable)
	return child, 0
}

func (n *OverlayNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return errno
	}
	origChild := n.origChildPath(name)
	// Resolve rejects an already-deleted path (own or ancestor whiteout)
	// even when the kernel held a stale cached inode.
	res := shadowBackend.Resolve(epochID, origChild)
	if !res.Exists {
		return syscall.ENOENT
	}
	// POSIX rmdir must fail with ENOTEMPTY on non-empty directories. Check
	// the MERGED view (backing + visible versions minus whiteouts), not any
	// single physical directory.
	if merged, err := shadowBackend.MergeReaddirVersions(epochID, origChild); err == nil && len(merged) > 0 {
		return syscall.ENOTEMPTY
	}
	if err := shadowBackend.RecordRmdir(epochID, origChild); err != nil {
		log.Printf("[overlay] RecordRmdir failed: %v", err)
		return syscall.EIO
	}
	return 0
}

func (n *OverlayNode) Unlink(ctx context.Context, name string) syscall.Errno {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return errno
	}
	origChild := n.origChildPath(name)
	res := shadowBackend.Resolve(epochID, origChild)
	if !res.Exists {
		return syscall.ENOENT
	}
	if err := shadowBackend.RecordUnlink(epochID, origChild); err != nil {
		log.Printf("[overlay] RecordUnlink failed: %v", err)
		return syscall.EIO
	}
	return 0
}

func (n *OverlayNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return errno
	}
	oldOrig := n.origChildPath(name)
	newParentNode, ok := newParent.(*OverlayNode)
	if !ok {
		return syscall.EINVAL
	}
	newOrig := newParentNode.origChildPath(newName)

	// Source must exist in the epoch's view (Resolve also rejects deleted
	// ancestors and records the read-from edge on the moved version).
	srcRes := shadowBackend.Resolve(epochID, oldOrig)
	if !srcRes.Exists {
		return syscall.ENOENT
	}
	var srcSt syscall.Stat_t
	if err := syscall.Lstat(srcRes.PhysicalPath, &srcSt); err != nil {
		return syscall.ENOENT
	}
	// Destination: renaming ONTO a deleted name is legal (it overwrites the
	// whiteout); only a deleted destination PARENT is an error.
	if pRes := shadowBackend.Resolve(epochID, filepath.Dir(newOrig)); filepath.Clean(filepath.Dir(newOrig)) != filepath.Clean(n.root.origDir) && !pRes.Exists {
		return syscall.ENOENT
	}

	// POSIX rename type/emptiness validation against the merged view the
	// user actually sees. Without this the version pair would be recorded,
	// but a later promotion would fail with EISDIR / ENOTDIR / ENOTEMPTY —
	// leaving the epoch permanently un-finalisable.
	dstRes := shadowBackend.Resolve(epochID, newOrig)
	if dstRes.Exists {
		var dstSt syscall.Stat_t
		if err := syscall.Lstat(dstRes.PhysicalPath, &dstSt); err == nil {
			srcIsDir := (srcSt.Mode & syscall.S_IFMT) == syscall.S_IFDIR
			dstIsDir := (dstSt.Mode & syscall.S_IFMT) == syscall.S_IFDIR
			switch {
			case srcIsDir && !dstIsDir:
				return syscall.ENOTDIR
			case !srcIsDir && dstIsDir:
				return syscall.EISDIR
			case srcIsDir && dstIsDir:
				// POSIX: dst dir must be empty (merged view).
				if merged, err := shadowBackend.MergeReaddirVersions(epochID, newOrig); err == nil && len(merged) > 0 {
					return syscall.ENOTEMPTY
				}
			}
		}
	}

	if err := shadowBackend.RecordRename(epochID, oldOrig, newOrig); err != nil {
		log.Printf("[overlay] RecordRename failed: %v", err)
		return fs.ToErrno(err)
	}
	return 0
}

// Setattr handles chmod/chown/truncate/utimes by routing to the epoch's own
// version. Truncation triggers a copy-up so the backing file is never
// resized.
func (n *OverlayNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	rel := n.relPath()
	if rel == "" {
		// Root: nothing meaningful to update on the orig side.
		return n.Getattr(ctx, fh, out)
	}
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return errno
	}

	// Reject before any attribute modification when the path is hidden by a
	// whiteout (own or ancestor) — stale cached inodes must not modify
	// already-deleted files.
	if res := shadowBackend.Resolve(epochID, n.origPath()); !res.Exists {
		return syscall.ENOENT
	}

	if th, ok := fh.(*trackedHandle); ok && th.onStage && th.epochID == epochID {
		// Fast path: the fd is known to point at this epoch's stage copy,
		// so applying chmod / chown / truncate / utimens via the fd is
		// safe and avoids re-running PrepareWrite.
		if sa, ok := fh.(fs.FileSetattrer); ok {
			if errno := sa.Setattr(ctx, in, out); errno != 0 {
				return errno
			}
			return n.Getattr(ctx, fh, out)
		}
	}
	// Either fh is nil, fh points at another epoch's version, or fh's fd
	// points directly at the backing file (R-only open). Delegating to
	// fh.Setattr there would mutate state outside this epoch's version —
	// violating the "backing is immutable" invariant. Force the path-based
	// route so PrepareWrite materialises the epoch's own version first.
	stagePath, err := shadowBackend.PrepareWrite(epochID, n.origPath())
	if err != nil {
		return fs.ToErrno(err)
	}

	if size, ok := in.GetSize(); ok {
		if err := os.Truncate(stagePath, int64(size)); err != nil {
			return fs.ToErrno(err)
		}
	}
	if mode, ok := in.GetMode(); ok {
		if err := os.Chmod(stagePath, os.FileMode(mode)); err != nil {
			return fs.ToErrno(err)
		}
	}
	if uid, uok := in.GetUID(); uok {
		gid, _ := in.GetGID()
		if err := os.Chown(stagePath, int(uid), int(gid)); err != nil {
			return fs.ToErrno(err)
		}
	} else if gid, gok := in.GetGID(); gok {
		if err := os.Chown(stagePath, -1, int(gid)); err != nil {
			return fs.ToErrno(err)
		}
	}
	// Time updates: each of atime/mtime can be (a) a specific value, (b)
	// "now", or (c) untouched. Untouched fields must keep their existing
	// on-disk value, so when only one of the two is set the other is read
	// from the stage file rather than passed as zero.
	atimeSet := in.Valid&(fuse.FATTR_ATIME|fuse.FATTR_ATIME_NOW) != 0
	mtimeSet := in.Valid&(fuse.FATTR_MTIME|fuse.FATTR_MTIME_NOW) != 0
	if atimeSet || mtimeSet {
		now := time.Now()
		var curATime, curMTime time.Time
		if !(atimeSet && mtimeSet) {
			if st, err := os.Stat(stagePath); err == nil {
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
		if err := os.Chtimes(stagePath, atime, mtime); err != nil {
			return fs.ToErrno(err)
		}
	}

	return n.Getattr(ctx, fh, out)
}

// Readlink resolves a symlink in the epoch's view.
func (n *OverlayNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	epochID, errno := epochForCtx(ctx)
	if errno != 0 {
		return nil, errno
	}
	res := shadowBackend.Resolve(epochID, n.origPath())
	if !res.Exists {
		return nil, syscall.ENOENT
	}
	// If the resolved object is NOT a symlink (e.g. the path was replaced
	// by a regular file), return EINVAL like the kernel does.
	st, err := os.Lstat(res.PhysicalPath)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return nil, syscall.EINVAL
	}
	target, err := os.Readlink(res.PhysicalPath)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	return []byte(target), 0
}

// --- main ---

func main() {
	log.SetFlags(log.Lmicroseconds)
	debug := flag.Bool("debug", false, "print debugging messages.")
	staging := flag.String("staging", "", "staging directory for the version store (required)")
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

	// Harden the control plane: forbid gaining privileges via a
	// setuid/setgid bit. Enabled only when already root: FUSE (un)mount
	// shells out to the setuid-root `fusermount3`, which a NON-root daemon
	// relies on to elevate -- no_new_privs would break that.
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
		root: &OverlayRoot{origDir: origDir},
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
			// the trackedHandle lock passthrough is exercised by the kernel.
			EnableLocks: true,
		},
	}
	server, err := fs.Mount(mntDir, root, opts)
	if err != nil {
		log.Fatalf("Mount fail: %v\n", err)
	}
	fmt.Printf("Mounted! orig=%q staging=%q\n", origDir, shadowBackend.StagingDir())

	// Tell the backend the mountpoint so commit-time writable-MAP_SHARED
	// quiescence can match /proc/<pid>/maps entries to stage copies.
	shadowBackend.SetMountDir(mntDir)

	// Rollback removes versions out-of-band (via the control socket, not
	// through the FUSE data path), so the kernel's dentry cache
	// (EntryTimeout) keeps serving stale positive entries for paths whose
	// version was just deleted. Invalidate those entries so the next lookup
	// re-resolves the merged view.
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
