package backend

import "testing"

// Tests for the pure /proc/<pid>/maps parser used by commit-time writable
// MAP_SHARED quiescence. The I/O-heavy quiesceMappings/quiesceRegion path needs
// a live frozen process + FUSE mount and is exercised by the integration
// harness, not here.

func TestParseWritableSharedMaps(t *testing.T) {
	mnt := "/tmp/shadow-mnt"
	maps := "" +
		// executable text: private r-x -> skip
		"55e000-55f000 r-xp 00000000 fd:00 100 /usr/bin/bash\n" +
		// writable private anon -> skip
		"7f0000-7f1000 rw-p 00000000 00:00 0 \n" +
		// read-only shared ShadowFS file -> skip (not writable)
		"7f2000-7f3000 r--s 00000000 fd:00 200 /tmp/shadow-mnt/ro.dat\n" +
		// writable shared, but NOT under the mount -> skip
		"7f4000-7f5000 rw-s 00000000 00:05 12 /dev/shm/seg\n" +
		// writable shared ShadowFS file at a non-zero file offset -> KEEP
		"7f6000-7f6800 rw-s 00001000 fd:00 300 /tmp/shadow-mnt/data/db.bin\n"

	regions := parseWritableSharedMaps(maps, mnt)
	if len(regions) != 1 {
		t.Fatalf("expected exactly 1 writable-shared ShadowFS region, got %d: %+v",
			len(regions), regions)
	}
	r := regions[0]
	if r.mountPath != "/tmp/shadow-mnt/data/db.bin" {
		t.Errorf("mountPath = %q", r.mountPath)
	}
	if r.start != 0x7f6000 || r.end != 0x7f6800 {
		t.Errorf("range = %#x-%#x", r.start, r.end)
	}
	if r.offset != 0x1000 {
		t.Errorf("offset = %#x, want 0x1000", r.offset)
	}
}

func TestParseWritableSharedMapsTrailingSlashMount(t *testing.T) {
	// A mountDir with a trailing slash must still match (SetMountDir cleans it,
	// but be defensive).
	maps := "aaaa-bbbb rw-s 00000000 fd:00 9 /m/f\n"
	if got := parseWritableSharedMaps(maps, "/m/"); len(got) != 1 {
		t.Fatalf("trailing-slash mount: expected 1 region, got %d", len(got))
	}
	// A path that merely shares a prefix string but is not under the mount dir
	// must NOT match (/m vs /mother).
	maps2 := "aaaa-bbbb rw-s 00000000 fd:00 9 /mother/f\n"
	if got := parseWritableSharedMaps(maps2, "/m"); len(got) != 0 {
		t.Fatalf("prefix-only path must not match, got %d", len(got))
	}
}
