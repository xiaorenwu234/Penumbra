package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"wokron/shadowfs/backend"
)

// The daemon used to wedge during the RQ3 scaling experiment: the log stopped
// mid-rollback, every Go thread sat in S, the orchestrator's callers went
// uninterruptible, and nothing was printed again until the process was killed.
// The reproducible symptom underneath all of that was
//
//	[backend] Rollback WAL barrier failed: WAL barrier: fsync:
//	  .../staging/metadata/.shadow_wal: bad file descriptor
//
// on a descriptor opened microseconds earlier. A stray close was landing on
// somebody else's file. Its source is trackedHandle.Release, which closed the
// descriptor through TrackedFD and then handed the SAME number back to
// fs.LoopbackFile.Release for a second syscall.Close. The comment there
// claimed the second close "returns EBADF which is silently ignored"; it does
// not. Closing a descriptor frees its number for immediate reuse by any other
// goroutine in the daemon, so the stale close lands on whichever descriptor
// took the number next -- the WAL file, an accepted control connection, or
// another epoch's stage copy. Note that it happened on EVERY file release, not
// only on cascade rollbacks, which is why three corruptions showed up in a few
// thousand rounds.
//
// These tests pin the replacement invariant: TrackedFD is the only closer, and
// a handle whose descriptor was force-closed by a cascade rollback refuses
// every operation that would touch the raw number. They do not claim to
// reproduce the full wedge -- fd corruption alone does not account for a daemon
// that stops logging from every goroutine without panicking, and /dev/fuse is
// never freed so it cannot be the victim. If the wedge returns, SIGQUIT the
// daemon: it does not install a handler for that signal, so the Go runtime
// dumps every goroutine stack to the log.

// newHandle opens `path` and wraps it the way openFileHandle does, registering
// the descriptor with the backend so a cascade rollback can reach it.
func newHandle(t *testing.T, path string, epoch backend.EpochID) (*trackedHandle, int) {
	t.Helper()
	fd, err := syscall.Open(path, syscall.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	tfd := backend.NewTrackedFD(fd)
	shadowBackend.RegisterFD(epoch, tfd)
	h := &trackedHandle{
		LoopbackFile: fs.NewLoopbackFile(fd).(*fs.LoopbackFile),
		tfd:          tfd,
		epochID:      epoch,
	}
	t.Cleanup(func() { _ = h.tfd.Close() })
	return h, fd
}

// useBackend installs a real backend in the package global the FUSE layer
// uses. Release calls UnregisterFD on it, so a nil global would panic and mask
// the behaviour under test.
func useBackend(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(orig, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := backend.NewBackend(staging, orig)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	prev := shadowBackend
	shadowBackend = b
	t.Cleanup(func() {
		b.Close()
		shadowBackend = prev
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReleaseDoesNotCloseADescriptorThatReusedTheNumber is the regression
// test for the wedge. It arranges the exact interleaving that the wild double
// close depended on: a cascade rollback force-closes the handle's descriptor,
// an unrelated open takes the freed number, and only THEN does the kernel's
// RELEASE arrive. A Release that delegates to LoopbackFile closes the
// unrelated descriptor, and the test catches it by stat'ing that descriptor
// afterwards.
func TestReleaseDoesNotCloseADescriptorThatReusedTheNumber(t *testing.T) {
	useBackend(t)
	dir := t.TempDir()

	victim := filepath.Join(dir, "victim.dat")
	writeFile(t, victim, "epoch data")
	h, fd := newHandle(t, victim, "ep-victim")

	// The cascade rollback of some other epoch reaches this handle's
	// descriptor and closes it, as CloseEpochFDs does.
	shadowBackend.CloseEpochFDs("ep-victim")
	if !h.dead() {
		t.Fatal("CloseEpochFDs did not mark the handle dead")
	}

	// The number is free now, and the next open anywhere in the daemon gets
	// it. That open is the WAL file, or a socket accept, in the real run.
	bystander := filepath.Join(dir, "bystander.dat")
	writeFile(t, bystander, "unrelated")
	reused, err := syscall.Open(bystander, syscall.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open bystander: %v", err)
	}
	defer syscall.Close(reused)
	if reused != fd {
		t.Fatalf("expected the bystander to be handed the freed number %d, got %d "+
			"-- the test no longer exercises the interleaving", fd, reused)
	}

	// The kernel's RELEASE for the rolled-back handle arrives last.
	if errno := h.Release(context.Background()); errno != 0 {
		t.Fatalf("Release: %v", errno)
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(reused, &st); err != nil {
		t.Fatalf("Release closed a live, unrelated descriptor that merely "+
			"reused the freed number %d: %v", reused, err)
	}
}

// TestReleaseClosesThroughTrackedFDOnly states the invariant directly: after
// Release, the embedded LoopbackFile must still hold the original number.
// LoopbackFile.Release sets its fd to -1, so a -1 here means the closing
// responsibility was handed back to it -- the bug -- even on paths where the
// recycled number happens not to be reused and nothing visibly breaks.
func TestReleaseClosesThroughTrackedFDOnly(t *testing.T) {
	useBackend(t)
	dir := t.TempDir()

	target := filepath.Join(dir, "target.dat")
	writeFile(t, target, "data")
	h, fd := newHandle(t, target, "ep-target")

	if errno := h.Release(context.Background()); errno != 0 {
		t.Fatalf("Release: %v", errno)
	}
	if !h.tfd.IsClosed() {
		t.Error("Release left the descriptor open")
	}
	if got, ok := h.LoopbackFile.PassthroughFd(); !ok || got != fd {
		t.Errorf("Release delegated to LoopbackFile.Release (fd=%d ok=%v); "+
			"TrackedFD must be the only closer, want the embedded fd left at %d",
			got, ok, fd)
	}

	// Idempotent, because RELEASE can follow a cascade rollback that already
	// closed everything.
	if errno := h.Release(context.Background()); errno != 0 {
		t.Errorf("second Release: %v", errno)
	}
}

// TestAForceClosedHandleRefusesEveryRawFdOperation covers the other half.
// Closing the descriptor is not enough: the embedded LoopbackFile still holds
// the number and would happily use it.
//
// The bystander file is opened BEFORE the operations, and that ordering is what
// makes the test mean anything. Against a merely free number the kernel answers
// EBADF by itself, so an unguarded operation "passes" for the wrong reason; the
// guards are only load-bearing once the number is live again, because then an
// unguarded operation SUCCEEDS -- against a file that has nothing to do with the
// rolled-back epoch. Read is the worst case: it hands the number to the kernel
// to splice FROM (fuse.ReadResultFd), so the agent is served the contents of
// whatever now owns it.
func TestAForceClosedHandleRefusesEveryRawFdOperation(t *testing.T) {
	useBackend(t)
	dir := t.TempDir()

	target := filepath.Join(dir, "target.dat")
	writeFile(t, target, "data")
	h, fd := newHandle(t, target, "ep-dead")
	shadowBackend.CloseEpochFDs("ep-dead")
	if !h.dead() {
		t.Fatal("CloseEpochFDs did not mark the handle dead")
	}

	const bystanderContent = "unrelated file that now owns the number"
	bystander := filepath.Join(dir, "bystander.dat")
	writeFile(t, bystander, bystanderContent)
	reused, err := syscall.Open(bystander, syscall.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open bystander: %v", err)
	}
	defer syscall.Close(reused)
	if reused != fd {
		t.Fatalf("expected the bystander to be handed the freed number %d, got %d "+
			"-- the operations below would hit a dead number and prove nothing",
			fd, reused)
	}

	ctx := context.Background()
	var st syscall.Stat_t
	var lk fuse.FileLock
	var sx fuse.StatxOut
	var attr fuse.AttrOut
	var setIn fuse.SetAttrIn
	buf := []byte("CORRUPT")

	cases := []struct {
		name string
		call func() syscall.Errno
	}{
		{"Read", func() syscall.Errno {
			_, e := h.Read(ctx, buf, 0)
			return e
		}},
		{"Write", func() syscall.Errno {
			_, e := h.Write(ctx, buf, 0)
			return e
		}},
		{"Flush", func() syscall.Errno { return h.Flush(ctx) }},
		{"Fsync", func() syscall.Errno { return h.Fsync(ctx, 0) }},
		{"Getattr", func() syscall.Errno { return h.Getattr(ctx, &attr) }},
		{"Setattr", func() syscall.Errno {
			return h.Setattr(ctx, &setIn, &attr)
		}},
		{"Allocate", func() syscall.Errno { return h.Allocate(ctx, 0, 0, 0) }},
		{"Lseek", func() syscall.Errno {
			_, e := h.Lseek(ctx, 0, 0)
			return e
		}},
		{"Ioctl", func() syscall.Errno {
			_, e := h.Ioctl(ctx, 0, 0, nil, nil)
			return e
		}},
		{"Statx", func() syscall.Errno { return h.Statx(ctx, 0, 0, &sx) }},
		{"Getlk", func() syscall.Errno {
			return h.Getlk(ctx, 0, &lk, 0, &lk)
		}},
		{"Setlk", func() syscall.Errno { return h.Setlk(ctx, 0, &lk, 0) }},
		{"Setlkw", func() syscall.Errno { return h.Setlkw(ctx, 0, &lk, 0) }},
	}
	for _, c := range cases {
		if got := c.call(); got != syscall.EBADF {
			t.Errorf("%s on a force-closed handle = %v, want EBADF -- it ran "+
				"against the live descriptor that reused the number", c.name, got)
		}
	}
	if got, ok := h.PassthroughFd(); ok || got != -1 {
		t.Errorf("PassthroughFd on a force-closed handle = (%d, %v), want (-1, false)",
			got, ok)
	}

	if err := syscall.Fstat(reused, &st); err != nil {
		t.Errorf("operations on a force-closed handle closed the descriptor that "+
			"reused number %d: %v", reused, err)
	}
	got, err := os.ReadFile(bystander)
	if err != nil {
		t.Fatalf("read bystander: %v", err)
	}
	if string(got) != bystanderContent {
		t.Errorf("operations on a force-closed handle wrote into the unrelated "+
			"file holding number %d: %q", reused, got)
	}
}

// TestPassthroughIsDisabledByDefault pins the DEFAULT (flag off) that keeps the
// multi-agent axis safe from the FUSE serve-loop deadlock, and the LIVE handle
// is the point: the wedge happened on ordinary Opens, not force-closed ones.
// The enabled path is covered by TestPassthroughEnabledReturnsBackingFdOnALiveHandle.
//
// A live trackedHandle used to return its real backing fd here unconditionally,
// so go-fuse registered it for passthrough (rawBridge.Open -> addBackingID ->
// Server.RegisterBackingFd), which takes Server.writeMu WHILE HOLDING the
// rawBridge mutex. The post-rollback dentry invalidation (notifyInvalidated ->
// Inode.NotifyEntry -> Server.writev) takes the same writeMu and then blocks in
// writev(/dev/fuse) until the kernel can take a dcache lock that an in-flight
// FUSE request is holding -- and that request can never be answered, because
// answering it needs the mutexes this notify sits on. The entire serve loop
// wedged and the agent's `cat` hung in D on the mount for good, while the
// backend kept ticking -- which is why the checkpoint-heartbeat watchdog, and
// every backend concurrency test, stayed green through it.
//
// Returning ok=false makes addBackingID register nothing, so the serve loop
// never touches writeMu and a notify that stalls in the kernel can no longer
// freeze lookups and opens. This asserts the daemon-side switch only: the full
// deadlock needs a real root mount with CAP_PASSTHROUGH, which a unit test
// cannot stand up -- exactly why it survived the suite and had to be caught with
// a live SIGQUIT dump.
func TestPassthroughIsDisabledByDefault(t *testing.T) {
	useBackend(t)
	prior := passthroughEnabled.Load()
	passthroughEnabled.Store(false)
	t.Cleanup(func() { passthroughEnabled.Store(prior) })
	f := filepath.Join(t.TempDir(), "live.dat")
	writeFile(t, f, "base")

	h, fd := newHandle(t, f, "ep-live")
	if h.dead() {
		t.Fatal("setup: handle is already force-closed; this must test a LIVE one")
	}
	// The embedded LoopbackFile still owns a usable descriptor, proving the
	// handle is live and that refusing passthrough is a deliberate policy rather
	// than a side effect of a closed fd.
	if got, ok := h.LoopbackFile.PassthroughFd(); !ok || got != fd {
		t.Fatalf("setup: embedded LoopbackFile fd = (%d, %v), want (%d, true)",
			got, ok, fd)
	}
	// The override must refuse passthrough regardless.
	if got, ok := h.PassthroughFd(); ok {
		t.Errorf("PassthroughFd on a LIVE handle = (%d, true), want (_, false): "+
			"go-fuse would register a backing fd and couple the serve loop's Open "+
			"path to Server.writeMu, deadlocking it against the rollback dentry "+
			"invalidation", got)
	}
}

// TestPassthroughEnabledReturnsBackingFdOnALiveHandle covers the opt-in path the
// launcher turns on for the SINGLE-EPOCH overhead axis: with the flag set, a
// live handle hands back its real backing fd so the kernel can serve read/write
// directly (the ~2x file-op speedup). This is safe only because a single-epoch
// workload has one opener per inode, satisfying the kernel's one-backing-file-
// per-inode rule; the multi-agent axis leaves the flag off.
func TestPassthroughEnabledReturnsBackingFdOnALiveHandle(t *testing.T) {
	useBackend(t)
	prior := passthroughEnabled.Load()
	passthroughEnabled.Store(true)
	t.Cleanup(func() { passthroughEnabled.Store(prior) })

	f := filepath.Join(t.TempDir(), "live.dat")
	writeFile(t, f, "base")
	h, fd := newHandle(t, f, "ep-pt-live")
	if h.dead() {
		t.Fatal("setup: handle is already force-closed; this must test a LIVE one")
	}
	got, ok := h.PassthroughFd()
	if !ok || got != fd {
		t.Errorf("PassthroughFd with the flag on, live handle = (%d, %v), want (%d, true)",
			got, ok, fd)
	}
}

// TestPassthroughEnabledStillRefusesAForceClosedHandle pins that enabling
// passthrough does NOT resurrect a cascade-rolled-back handle: even with the
// flag on, a dead handle returns (-1, false), so the kernel is never pointed at
// a backing file whose epoch was force-closed. Without this, passthrough would
// bypass the EBADF guard every other trackedHandle method enforces.
func TestPassthroughEnabledStillRefusesAForceClosedHandle(t *testing.T) {
	useBackend(t)
	prior := passthroughEnabled.Load()
	passthroughEnabled.Store(true)
	t.Cleanup(func() { passthroughEnabled.Store(prior) })

	f := filepath.Join(t.TempDir(), "dead.dat")
	writeFile(t, f, "base")
	h, _ := newHandle(t, f, "ep-pt-dead")
	shadowBackend.CloseEpochFDs("ep-pt-dead")
	if !h.dead() {
		t.Fatal("setup: CloseEpochFDs did not mark the handle dead")
	}
	if got, ok := h.PassthroughFd(); ok || got != -1 {
		t.Errorf("PassthroughFd with the flag on, force-closed handle = (%d, %v), "+
			"want (-1, false): the kernel would keep serving a dead backing file", got, ok)
	}
}
