#!/usr/bin/env python3
"""CRI path-convention tests for policy_ir.

ShadowObserve records an event's canonical path by walking d_parent until it
repeats, so a file on any non-root filesystem is recorded RELATIVE TO ITS MOUNT
POINT: the sealed trace of RQ2 exp2 carries "/exp2/reject-<run>-0.txt" for a
write to "/tmp/shadow-rq2-test/mnt/exp2/reject-<run>-0.txt" on the ShadowFS FUSE
mount, while the same write's backing copy under /tmp (root filesystem) is
recorded host-absolute. A policy written in host-absolute paths therefore never
matched the audited events, and exp2's `deny WRITE <fuse file>` produced 0
violations.

These tests pin the projection (to_cri_path / load_mount_table) that closes that
gap, and that audit rules and BPF whitelist prefixes are projected identically.

Run: python3 policy/test_cri_paths.py
"""

import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJ = os.path.dirname(_HERE)
if _PROJ not in sys.path:
    sys.path.insert(0, _PROJ)

from policy.policy_ir import (  # noqa: E402
    PolicyIR, load_mount_table, to_cri_path,
)

# The ShadowFS FUSE mount used by the RQ2 experiments.
FUSE_MNT = "/tmp/shadow-rq2-test/mnt"

# A synthetic mount table in mountinfo format: root fs, the FUSE mount, a
# tmpfs, a bind mount of a sub-tree, and a mount point containing a space
# (mountinfo escapes it as \040). Plus garbage lines that must be ignored.
MOUNTINFO = """\
22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw,errors=continue
25 22 0:23 / /proc rw,nosuid - proc proc rw
101 22 0:54 / /tmp/shadow-rq2-test/mnt rw,nosuid,nodev - fuse.rawBridge rawBridge rw,user_id=0,group_id=0,allow_other
120 22 0:29 / /run rw,nosuid,nodev - tmpfs tmpfs rw,mode=755
130 22 8:2 /srv/data /mnt/bind rw,relatime - ext4 /dev/sda2 rw
140 22 0:55 / /mnt/my\\040dir rw,relatime - tmpfs tmpfs rw
garbage line without a separator
150 22 0:56
"""


class MountTableTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="mountinfo-", dir=_HERE)
        with os.fdopen(fd, "w") as f:
            f.write(MOUNTINFO)
        self.addCleanup(os.unlink, self.path)
        self.table = load_mount_table(self.path)

    def test_parses_mount_point_and_sb_root(self):
        self.assertIn((FUSE_MNT, "/"), self.table)
        self.assertIn(("/mnt/bind", "/srv/data"), self.table)
        self.assertIn(("/", "/"), self.table)

    def test_longest_mount_point_first(self):
        points = [mp for mp, _ in self.table]
        self.assertEqual(points[0], FUSE_MNT,
                         "longest prefix must win over shorter ones")
        self.assertLess(points.index("/run"), points.index("/"))

    def test_octal_escapes_decoded(self):
        self.assertIn(("/mnt/my dir", "/"), self.table)

    def test_garbage_lines_ignored(self):
        for mp, root in self.table:
            self.assertTrue(mp.startswith("/"), f"bad mount point {mp!r}")
            self.assertTrue(root.startswith("/"), f"bad sb root {root!r}")
        self.assertEqual(len(self.table), 6)

    def test_unreadable_table_raises(self):
        with self.assertRaises(ValueError):
            load_mount_table(os.path.join(_HERE, "no-such-mountinfo"))


class ToCriPathTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="mountinfo-", dir=_HERE)
        with os.fdopen(fd, "w") as f:
            f.write(MOUNTINFO)
        self.addCleanup(os.unlink, self.path)
        self.table = load_mount_table(self.path)

    def cri(self, path):
        return to_cri_path(path, self.table)

    def test_fuse_path_loses_mount_prefix(self):
        # Exactly the exp2 reject-trace evidence.
        self.assertEqual(self.cri(f"{FUSE_MNT}/exp2/reject-1-0.txt"),
                         "/exp2/reject-1-0.txt")

    def test_root_filesystem_path_unchanged(self):
        # /tmp is NOT a mount here, so the staging backing path stays absolute
        # -- matching the same trace, which recorded it host-absolute.
        staging = ("/tmp/shadow-rq2-test/staging/epochs/ep-1/versions/16/"
                   "files/exp2/reject-1-0.txt")
        self.assertEqual(self.cri(staging), staging)
        self.assertEqual(self.cri("/var/lib/shadow-proxy/sessions/s.log"),
                         "/var/lib/shadow-proxy/sessions/s.log")

    def test_mount_point_itself_is_root(self):
        self.assertEqual(self.cri(FUSE_MNT), "/")

    def test_component_boundary_not_prefix_of_longer_name(self):
        # "/tmp/shadow-rq2-test/mntfoo" is NOT under the mount point.
        self.assertEqual(self.cri(FUSE_MNT + "foo/x"), FUSE_MNT + "foo/x")

    def test_tmpfs_and_nested_mounts(self):
        self.assertEqual(self.cri("/run/user/1000/x"), "/user/1000/x")
        self.assertEqual(self.cri("/proc/self/mountinfo"), "/self/mountinfo")

    def test_bind_mount_reattaches_source_subtree(self):
        # The dentry walk reports the SOURCE path of a bind mount.
        self.assertEqual(self.cri("/mnt/bind/a.txt"), "/srv/data/a.txt")
        self.assertEqual(self.cri("/mnt/bind"), "/srv/data")

    def test_root_and_empty_patterns_preserved(self):
        self.assertEqual(self.cri("/"), "/")
        self.assertEqual(self.cri(""), "")


class ProjectionTest(unittest.TestCase):
    """The IR projections must agree with each other and with the observer."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="mountinfo-", dir=_HERE)
        with os.fdopen(fd, "w") as f:
            f.write(MOUNTINFO)
        self.addCleanup(os.unlink, self.path)
        self.table = load_mount_table(self.path)

    def test_exp2_reject_policy_denies_the_recorded_path(self):
        target = f"{FUSE_MNT}/exp2/reject-72107459-0.txt"
        ir = PolicyIR.from_allowed_ops([
            {"event_type": "*", "action": "allow", "path_pattern": "/"},
            {"event_type": "WRITE", "action": "deny", "path_pattern": target},
        ])
        rules = ir.to_audit_rules(self.table)
        self.assertEqual(rules[0]["path_pattern"], "/")
        self.assertEqual(rules[1]["action"], "deny")
        self.assertEqual(rules[1]["path_pattern"],
                         "/exp2/reject-72107459-0.txt",
                         "the deny must be expressed in the recorded convention")

    def test_audit_and_whitelist_projections_agree(self):
        ops = [{"event_type": "WRITE", "action": "allow",
                "path_pattern": f"{FUSE_MNT}/exp2"}]
        ir = PolicyIR.from_allowed_ops(ops)
        audit = ir.to_audit_rules(self.table)[0]["path_pattern"]
        wl = ir.to_bpf_whitelist(self.table)[0]["path_prefix"]
        self.assertEqual(audit, wl)
        self.assertEqual(audit, "/exp2")

    def test_deny_rules_are_absent_from_the_whitelist(self):
        ir = PolicyIR.from_allowed_ops([
            {"event_type": "*", "action": "allow", "path_pattern": "/"},
            {"event_type": "WRITE", "action": "deny",
             "path_pattern": f"{FUSE_MNT}/exp2/secret"},
        ])
        wl = ir.to_bpf_whitelist(self.table)
        self.assertEqual(len(wl), 1)
        self.assertEqual(wl[0]["event_type"], 0xFFFF)

    def test_unreadable_mount_table_fails_closed(self):
        ir = PolicyIR.from_allowed_ops(
            [{"event_type": "WRITE", "action": "deny",
              "path_pattern": f"{FUSE_MNT}/exp2/x"}])
        # The orchestrator wraps both projections in `except ValueError` and
        # contains the epoch rather than auditing against a policy whose path
        # rules can never match.
        with self.assertRaises(ValueError):
            ir.to_audit_rules(load_mount_table("/nonexistent/mountinfo"))


@unittest.skipUnless(
    os.path.exists("/proc/self/mountinfo"), "needs a Linux mount table")
class LiveHostTest(unittest.TestCase):
    """Projection against the host's real mount table (no assertions about
    which mounts exist -- only that the projection is self-consistent)."""

    def test_live_table_projects_every_mount_point_to_its_sb_root(self):
        table = load_mount_table()
        self.assertTrue(table)
        for mount_point, sb_root in table:
            if mount_point == "/":
                continue
            expected = ("/" if sb_root == "/" else sb_root.rstrip("/")) or "/"
            self.assertEqual(to_cri_path(mount_point, table), expected)

    def test_live_root_filesystem_paths_unchanged(self):
        table = load_mount_table()
        self.assertEqual(to_cri_path("/etc/passwd", table), "/etc/passwd")


if __name__ == "__main__":
    unittest.main(verbosity=2)
