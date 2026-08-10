#!/usr/bin/env python3
"""
Effect coverage tests for the unified (class | op<<8) event model and the
fine-grained process-layer policy (P0-5 / P0-6 / P0-7).

Four areas:
  1. to_proc_policy() compilation — class-wide allow vs fine-grained endpoint
     maps, deny dominance, contradiction rejection (P0-5).
  2. Event encoding consistency — every legacy event name round-trips through
     event_name_to_type / decode_event_type and lands in the right effect_class
     (P0-6).
  3. _release_group_members — ALL SCC members are released (not just the
     primary cgroup) and the fine-grained proc_policy is forwarded to every
     member's continue_by_cgroup (P0-7).
  4. Three-phase effect decision skeleton — SPECULATIVE / AUTHORIZED_PENDING
     release without proc_policy (allow-all) vs ENFORCED release with a
     compiled fine-grained proc_policy (mode 2, default-deny at endpoint).

No live services needed: pure unit tests with FakeClient stubs, mirroring
test_release_path.py / test_finalization.py.
"""

import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.policy_ir import (
    PolicyIR, CLASS_IDS, IPC_TYPE_IDS, OP_IDS, SCHEMA,
    event_name_to_type, decode_event_type,
)
from shadow_orchestrator import ShadowOrchestrator


# ─── helpers (mirror test_release_path.py / test_finalization.py) ─────────

class FakeClient:
    """Records every request and returns whatever `handler(req)` produces."""

    def __init__(self, handler):
        self._handler = handler
        self.calls = []

    def request(self, req):
        self.calls.append(dict(req))
        return self._handler(req)

    def actions(self):
        return [c["action"] for c in self.calls]


def _bare_orch(proc_handler, fs_handler):
    """Build an orchestrator with fake clients and no sockets/threads."""
    orch = ShadowOrchestrator.__new__(ShadowOrchestrator)
    orch.proc_client = FakeClient(proc_handler)
    orch.fs_client = FakeClient(fs_handler)
    orch._pending_release = set()
    orch._pending_lock = threading.Lock()
    orch._pending_ack = set()
    orch._pending_ack_lock = threading.Lock()
    orch._release_lock = threading.RLock()
    return orch


class _NullJournal:
    """No-op durable journal stub."""

    def append(self, *args, **kwargs):
        pass


# ═══════════════════════════════════════════════════════════════
# 1. to_proc_policy compilation (P0-5)
# ═══════════════════════════════════════════════════════════════

class TestProcPolicyCompilation(unittest.TestCase):
    """Verify to_proc_policy() emits the right class modes + endpoint maps."""

    def _pp(self, ops):
        return PolicyIR.from_allowed_ops(ops).to_proc_policy()

    def test_operation_wide_allow_no_endpoint(self):
        """allow CONNECT without endpoint -> only NETWORK/CONNECT mode 1."""
        pp = self._pp([{"event_type": "CONNECT", "action": "allow",
                        "path_pattern": "/tmp/"}])
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        self.assertEqual(modes.get((CLASS_IDS["NETWORK"], OP_IDS[("NETWORK", "CONNECT")])), 1)
        self.assertNotIn((CLASS_IDS["NETWORK"], OP_IDS[("NETWORK", "BIND")]), modes)
        self.assertEqual(pp["network"], [], "no endpoint -> no fine entries")

    def test_network_fine_grained(self):
        """allow CONNECT + endpoint -> class NETWORK mode 2 + network entry."""
        pp = self._pp([{
            "event_type": "CONNECT", "action": "allow", "path_pattern": "/",
            "endpoint": {"family": 2, "addr": 16777343, "port": 443},
        }])
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        self.assertEqual(modes.get((CLASS_IDS["NETWORK"], OP_IDS[("NETWORK", "CONNECT")])), 2)
        self.assertEqual(len(pp["network"]), 1)
        e = pp["network"][0]
        self.assertEqual(e["operation"], OP_IDS[("NETWORK", "CONNECT")])
        self.assertEqual((e["family"], e["addr"], e["port"]), (2, 16777343, 443))
        self.assertEqual(e["allow"], 1)

    def test_ipc_fine_grained(self):
        """allow SHM + endpoint -> class IPC mode 2 + ipc entry."""
        pp = self._pp([{
            "event_type": "SHM", "action": "allow", "path_pattern": "/",
            "endpoint": {"ipc_type": "SHM", "target": 12345},
        }])
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        self.assertEqual(modes.get((CLASS_IDS["IPC"], OP_IDS[("IPC", "SYSV_SHM")])), 2)
        self.assertEqual(len(pp["ipc"]), 1)
        self.assertEqual(pp["ipc"][0]["operation"], OP_IDS[("IPC", "SYSV_SHM")])
        self.assertEqual(pp["ipc"][0]["ipc_type"], IPC_TYPE_IDS["SHM"])
        self.assertEqual(pp["ipc"][0]["target"], 12345)
        self.assertEqual(pp["ipc"][0]["allow"], 1)

    def test_signal_fine_grained(self):
        """allow KILL + endpoint -> class SIGNAL mode 2 + signal entry."""
        pp = self._pp([{
            "event_type": "KILL", "action": "allow", "path_pattern": "/",
            "endpoint": {"target_cgroup": 999},
        }])
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        self.assertEqual(modes.get((CLASS_IDS["SIGNAL"], OP_IDS[("SIGNAL", "KILL")])), 2)
        self.assertEqual(len(pp["signal"]), 1)
        self.assertEqual(pp["signal"][0]["operation"], OP_IDS[("SIGNAL", "KILL")])
        self.assertEqual(pp["signal"][0]["target_cgroup"], 999)
        self.assertEqual(pp["signal"][0]["allow"], 1)

    def test_deny_with_endpoint_emits_deny_entry(self):
        """deny CONNECT + endpoint -> mode 2 + network entry allow=0."""
        pp = self._pp([{
            "event_type": "CONNECT", "action": "deny", "path_pattern": "/",
            "endpoint": {"family": 2, "addr": 0, "port": 80},
        }])
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        self.assertEqual(modes.get((CLASS_IDS["NETWORK"], OP_IDS[("NETWORK", "CONNECT")])), 2)
        self.assertEqual(pp["network"][0]["allow"], 0)

    def test_deny_dominates_conflicting_endpoint(self):
        """Same endpoint allow+deny -> single entry with allow=0."""
        ep = {"family": 2, "addr": 0, "port": 443}
        pp = self._pp([
            {"event_type": "CONNECT", "action": "allow", "path_pattern": "/",
             "endpoint": ep},
            {"event_type": "CONNECT", "action": "deny", "path_pattern": "/",
             "endpoint": ep},
        ])
        self.assertEqual(len(pp["network"]), 1)
        self.assertEqual(pp["network"][0]["allow"], 0)

    def test_contradictory_class_allow_and_endpoint_raises(self):
        """Class-wide allow + endpoint rule for same class -> ValueError."""
        with self.assertRaises(ValueError):
            self._pp([
                {"event_type": "CONNECT", "action": "allow",
                 "path_pattern": "/"},
                {"event_type": "CONNECT", "action": "allow",
                 "path_pattern": "/",
                 "endpoint": {"family": 2, "addr": 0, "port": 80}},
            ])

    def test_wildcard_allow_class_mode(self):
        """Wildcard '*' allow -> every class mode 1 (allow-all)."""
        pp = self._pp([{"event_type": "*", "action": "allow",
                        "path_pattern": "/"}])
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        for cls_name, cls_id in CLASS_IDS.items():
            for op_name, op_id in SCHEMA["effect_classes"][cls_name]["operations"].items():
                self.assertEqual(modes.get((cls_id, op_id)), 1,
                                 f"{cls_name}/{op_name} should be allow-all")

    def test_wildcard_with_endpoint_raises(self):
        """Wildcard event_type cannot carry an endpoint (fail-closed)."""
        with self.assertRaises(ValueError):
            self._pp([{"event_type": "*", "action": "allow",
                       "path_pattern": "/",
                       "endpoint": {"family": 2, "addr": 0, "port": 80}}])

    def test_multiple_classes_independent(self):
        """NETWORK allow + IPC fine + SIGNAL fine -> independent modes."""
        pp = self._pp([
            {"event_type": "CONNECT", "action": "allow", "path_pattern": "/"},
            {"event_type": "SHM", "action": "allow", "path_pattern": "/",
             "endpoint": {"ipc_type": 1, "target": 0}},
            {"event_type": "KILL", "action": "allow", "path_pattern": "/",
             "endpoint": {"target_cgroup": 0}},
        ])
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        self.assertEqual(modes[(CLASS_IDS["NETWORK"], OP_IDS[("NETWORK", "CONNECT")])], 1)
        self.assertEqual(modes[(CLASS_IDS["IPC"], OP_IDS[("IPC", "SYSV_SHM")])], 2)
        self.assertEqual(modes[(CLASS_IDS["SIGNAL"], OP_IDS[("SIGNAL", "KILL")])], 2)
    def test_operation_allow_does_not_broaden_to_same_class_siblings(self):
        cases = [
            ("CONNECT", "NETWORK", "CONNECT", "BIND"),
            ("MOUNT", "SYSTEM", "MOUNT", "BPF"),
            ("KILL", "SIGNAL", "KILL", "PTRACE"),
        ]
        for event_name, cls_name, allowed_op, forbidden_op in cases:
            with self.subTest(event=event_name):
                pp = PolicyIR.from_allowed_ops([{
                    "event_type": event_name, "action": "allow", "path_pattern": "/",
                }]).to_proc_policy()
                modes = {(c["effect_class"], c["operation"]): c["mode"]
                         for c in pp["classes"]}
                self.assertEqual(modes[(CLASS_IDS[cls_name], OP_IDS[(cls_name, allowed_op)])], 1)
                self.assertNotIn((CLASS_IDS[cls_name], OP_IDS[(cls_name, forbidden_op)]), modes)


# ═══════════════════════════════════════════════════════════════
# 2. Event encoding consistency (P0-6)
# ═══════════════════════════════════════════════════════════════

class TestEventEncodingConsistency(unittest.TestCase):
    """Verify the unified (class | op<<8) encoding round-trips correctly."""

    def test_encode_decode_roundtrip(self):
        """event_name_to_type -> decode_event_type preserves class+op."""
        cases = [
            ("CONNECT", ("NETWORK", "CONNECT")),
            ("BIND", ("NETWORK", "BIND")),
            ("SEND", ("NETWORK", "SEND")),
            ("SHM", ("IPC", "SYSV_SHM")),
            ("MSG", ("IPC", "SYSV_MSG")),
            ("SEM", ("IPC", "SYSV_SEM")),
            ("MQ", ("IPC", "POSIX_MQ")),
            ("KILL", ("SIGNAL", "KILL")),
            ("PTRACE", ("SIGNAL", "PTRACE")),
            ("WRITE_OUT", ("OUTPUT", "WRITE_OUT")),
            ("EXEC", ("PRIVILEGE", "EXEC_PRIV")),
        ]
        for name, (cls_name, op_name) in cases:
            etype = event_name_to_type(name)
            self.assertGreater(etype, 0, f"{name} should map to a positive type")
            dcls, dop = decode_event_type(etype)
            self.assertEqual(dcls, CLASS_IDS[cls_name],
                             f"{name}: class {dcls} != {CLASS_IDS[cls_name]}")
            self.assertEqual(dop, OP_IDS[(cls_name, op_name)],
                             f"{name}: op {dop} != {OP_IDS[(cls_name, op_name)]}")

    def test_low_byte_is_class(self):
        """decode_event_type: low byte = effect_class."""
        etype = event_name_to_type("CONNECT")
        self.assertEqual(etype & 0xFF, CLASS_IDS["NETWORK"])

    def test_high_byte_is_op(self):
        """decode_event_type: high byte = operation."""
        etype = event_name_to_type("CONNECT")
        self.assertEqual((etype >> 8) & 0xFF, OP_IDS[("NETWORK", "CONNECT")])

    def test_network_events_share_class(self):
        """CONNECT/BIND/SEND all decode to NETWORK class."""
        for name in ("CONNECT", "BIND", "SEND"):
            cls, _ = decode_event_type(event_name_to_type(name))
            self.assertEqual(cls, CLASS_IDS["NETWORK"])

    def test_ipc_events_share_class(self):
        """SHM/MSG/SEM/MQ all decode to IPC class."""
        for name in ("SHM", "MSG", "SEM", "MQ"):
            cls, _ = decode_event_type(event_name_to_type(name))
            self.assertEqual(cls, CLASS_IDS["IPC"])

    def test_signal_events_share_class(self):
        """KILL/PTRACE decode to SIGNAL class."""
        for name in ("KILL", "PTRACE"):
            cls, _ = decode_event_type(event_name_to_type(name))
            self.assertEqual(cls, CLASS_IDS["SIGNAL"])

    def test_wildcard_is_minus_one(self):
        """'*' / 'ANY' -> -1 (not a valid encoded event)."""
        self.assertEqual(event_name_to_type("*"), -1)
        self.assertEqual(event_name_to_type("ANY"), -1)

    def test_distinct_ops_in_same_class_distinct_types(self):
        """CONNECT and BIND share class but have distinct event_types."""
        t_conn = event_name_to_type("CONNECT")
        t_bind = event_name_to_type("BIND")
        self.assertNotEqual(t_conn, t_bind)
        self.assertEqual(t_conn & 0xFF, t_bind & 0xFF,
                         "same class -> same low byte")


# ═══════════════════════════════════════════════════════════════
# 3. _release_group_members — SCC full-member release (P0-7)
# ═══════════════════════════════════════════════════════════════

class TestReleaseGroupMembers(unittest.TestCase):
    """Verify ALL SCC members are released and proc_policy is forwarded."""

    def _orch(self, proc_handler, fs_handler):
        orch = _bare_orch(proc_handler, fs_handler)
        orch._journal = _NullJournal()
        return orch

    def _fs_with_agents(self, mapping, ack_ok=True):
        """fs handler: list_agents returns mapping {epoch_id: cgroup_id}."""
        agents_info = [{"epoch_id": eid, "cgroup_id": cg}
                       for eid, cg in mapping.items()]

        def fs(req):
            a = req["action"]
            if a == "list_agents":
                return {"status": "ok", "agents_info": agents_info}
            if a == "ack_release_group":
                return {"status": "ok"} if ack_ok else {"status": "error"}
            if a == "can_release":
                return {"status": "ok", "releasable": True}
            return {"status": "ok"}
        return fs

    def _proc_ok(self):
        """proc handler: all actions succeed, frozen=[1]."""
        def proc(req):
            a = req["action"]
            if a == "list_frozen":
                return {"status": "ok", "frozen": [1]}
            if a == "commit_by_cgroup":
                return {"status": "ok"}
            if a == "continue_by_cgroup":
                return {"status": "ok", "pids": [1]}
            return {"status": "ok"}
        return proc

    def _policy(self):
        return {"classes": [{"effect_class": CLASS_IDS["NETWORK"],
                              "operation": OP_IDS[("NETWORK", "CONNECT")],
                              "mode": 1}],
                "network": [], "ipc": [], "signal": []}

    def test_releases_all_members_not_just_primary(self):
        """3-member SCC -> continue_by_cgroup called for every member cgroup."""
        mapping = {"e1": "/cg-a", "e2": "/cg-b", "e3": "/cg-primary"}
        orch = self._orch(self._proc_ok(), self._fs_with_agents(mapping))
        out, primary_ok = orch._release_group_members(
            group_id=1, members=["e1", "e2", "e3"],
            graph_generation=1, primary_cgroup="/cg-primary",
            proc_policy=self._policy())
        resumes = [c["cgroup_id"] for c in orch.proc_client.calls
                   if c["action"] == "continue_by_cgroup"]
        self.assertEqual(sorted(resumes), ["/cg-a", "/cg-b", "/cg-primary"])
        self.assertTrue(primary_ok)

    def test_forwards_proc_policy_to_every_member(self):
        """proc_policy appears in every member's continue_by_cgroup request."""
        mapping = {"e1": "/cg-a", "e2": "/cg-b"}
        orch = self._orch(self._proc_ok(), self._fs_with_agents(mapping))
        pp = self._policy()
        orch._release_group_members(
            group_id=1, members=["e1", "e2"], graph_generation=1,
            primary_cgroup="/cg-a", proc_policy=pp)
        resume_reqs = [c for c in orch.proc_client.calls
                       if c["action"] == "continue_by_cgroup"]
        self.assertEqual(len(resume_reqs), 2)
        for r in resume_reqs:
            self.assertEqual(r.get("policy"), pp)

    def test_no_proc_policy_fails_closed_without_release(self):
        """proc_policy=None -> no release; group remains parked."""
        mapping = {"e1": "/cg-a"}
        orch = self._orch(self._proc_ok(), self._fs_with_agents(mapping))
        orch._release_group_members(
            group_id=1, members=["e1"], graph_generation=1,
            primary_cgroup="/cg-a")
        resume_reqs = [c for c in orch.proc_client.calls
                       if c["action"] == "continue_by_cgroup"]
        self.assertEqual(len(resume_reqs), 0)
        self.assertIn(1, orch._pending_groups)

    def test_partial_failure_defers_failing_member(self):
        """One member's resume fails -> parked as group-level retry state."""
        mapping = {"e1": "/cg-ok", "e2": "/cg-fail", "e3": "/cg-ok2"}

        def proc(req):
            a = req["action"]
            if a == "list_frozen":
                return {"status": "ok", "frozen": [1]}
            if a == "commit_by_cgroup":
                return {"status": "ok"}
            if a == "continue_by_cgroup":
                if req["cgroup_id"] == "/cg-fail":
                    return {"status": "error", "message": "boom"}
                return {"status": "ok", "pids": [1]}
            return {"status": "ok"}

        orch = self._orch(proc, self._fs_with_agents(mapping))
        out, primary_ok = orch._release_group_members(
            group_id=1, members=["e1", "e2", "e3"],
            graph_generation=1, primary_cgroup="/cg-ok",
            proc_policy=self._policy())
        self.assertIn(1, orch._pending_groups)
        pending = orch._pending_groups[1]
        self.assertEqual(pending["member_cgroups"], ["/cg-ok", "/cg-fail", "/cg-ok2"])
        self.assertNotIn("/cg-fail", pending["released_cgroups"])
        self.assertIn("/cg-ok", pending["released_cgroups"])
        self.assertTrue(primary_ok,
                        "primary released even though a sibling failed")
        self.assertNotIn("ack_release_group", orch.fs_client.actions(),
                         "group ack must wait for every member release")

    def test_missing_member_cgroup_blocks_release_and_ack(self):
        """Missing member mapping -> fail closed; no partial release or group ack."""
        mapping = {"e1": "/cg-a"}
        orch = self._orch(self._proc_ok(), self._fs_with_agents(mapping))
        out, primary_ok = orch._release_group_members(
            group_id=9, members=["e1", "e2"], graph_generation=1,
            primary_cgroup="/cg-a", proc_policy=self._policy())
        self.assertEqual(out, {})
        self.assertFalse(primary_ok)
        self.assertIn(9, orch._pending_groups)
        self.assertNotIn("continue_by_cgroup", orch.proc_client.actions())
        self.assertNotIn("ack_release_group", orch.fs_client.actions())

    def test_single_group_ack_for_all_members(self):
        """Multiple members -> exactly one ack_release_group call."""
        mapping = {"e1": "/cg-a", "e2": "/cg-b", "e3": "/cg-c"}
        orch = self._orch(self._proc_ok(), self._fs_with_agents(mapping))
        orch._release_group_members(
            group_id=42, members=["e1", "e2", "e3"],
            graph_generation=1, primary_cgroup="/cg-a",
            proc_policy=self._policy())
        acks = [c for c in orch.fs_client.actions()
                if c == "ack_release_group"]
        self.assertEqual(len(acks), 1)

    def test_journal_release_intent_recorded(self):
        """journal_release_intent=True -> journal.append called with group info."""
        recorded = []

        class _Journal:
            def append(self, *a, **kw):
                recorded.append((a, kw))

        mapping = {"e1": "/cg-a"}
        orch = self._orch(self._proc_ok(), self._fs_with_agents(mapping))
        orch._journal = _Journal()
        orch._release_group_members(
            group_id=7, members=["e1"], graph_generation=3,
            primary_cgroup="/cg-a", journal_release_intent=True,
            epoch_id="epoch-7", proc_policy=self._policy())
        self.assertTrue(recorded, "release_intent must be journalled")
        _, kw = recorded[0]
        self.assertEqual(kw.get("group_id"), 7)
        self.assertEqual(kw.get("graph_generation"), 3)
        self.assertEqual(kw.get("epoch"), "epoch-7")


# ═══════════════════════════════════════════════════════════════
# 4. Three-phase effect decision skeleton
#    SPECULATIVE / AUTHORIZED_PENDING -> fence (no proc_policy on release)
#    ENFORCED                          -> per-policy (proc_policy forwarded)
# ═══════════════════════════════════════════════════════════════

class TestThreePhaseEffectDecisions(unittest.TestCase):
    """Skeleton for the three epoch-mode effect decision paths.

    In the BPF layer (shadow_proc.bpf.c check_policy_detail):
      MODE_SPECULATIVE (0)        -> DECISION_FENCE (block + notify)
      MODE_AUTHORIZED_PENDING (1) -> DECISION_FENCE (block + notify)
      MODE_ENFORCED (2)           -> DECISION_ALLOW / DECISION_DENY (per policy)

    The orchestrator cannot exercise the kernel-side decision directly, but it
    drives the transitions and compiles/forwards the proc_policy that governs
    ENFORCED mode. These tests assert the orchestrator-side invariants.
    """

    def _proc_ok(self):
        def proc(req):
            a = req["action"]
            if a == "list_frozen":
                return {"status": "ok", "frozen": [1]}
            if a == "commit_by_cgroup":
                return {"status": "ok"}
            if a == "continue_by_cgroup":
                return {"status": "ok", "pids": [1]}
            return {"status": "ok"}
        return proc

    def _fs_ok(self, req):
        return {"status": "ok"}

    def test_speculative_release_no_proc_policy(self):
        """SPECULATIVE/AUTHORIZED_PENDING: release without proc_policy ->
        continue_by_cgroup has no 'policy' key (allow-all semantics)."""
        orch = _bare_orch(self._proc_ok(), self._fs_ok)
        ok, out = orch._release_proc("/cg-spec")
        self.assertTrue(ok)
        resume = [c for c in orch.proc_client.calls
                  if c["action"] == "continue_by_cgroup"]
        self.assertEqual(len(resume), 1)
        self.assertNotIn("policy", resume[0])

    def test_enforced_release_forwards_proc_policy(self):
        """ENFORCED: release WITH proc_policy -> continue_by_cgroup carries
        'policy' so ShadowProc enforces fine-grained rules (not allow-all)."""
        pp = PolicyIR.from_allowed_ops([{
            "event_type": "CONNECT", "action": "allow", "path_pattern": "/",
            "endpoint": {"family": 2, "addr": 0, "port": 443},
        }]).to_proc_policy()
        orch = _bare_orch(self._proc_ok(), self._fs_ok)
        ok, out = orch._release_proc("/cg-enf", proc_policy=pp)
        self.assertTrue(ok)
        resume = [c for c in orch.proc_client.calls
                  if c["action"] == "continue_by_cgroup"]
        self.assertEqual(len(resume), 1)
        self.assertEqual(resume[0].get("policy"), pp)

    def test_enforced_policy_compiles_to_fine_mode(self):
        """ENFORCED fine-grained policy: to_proc_policy emits mode 2 (not 1)
        with endpoint entries, so BPF default-denies at the endpoint level."""
        pp = PolicyIR.from_allowed_ops([{
            "event_type": "CONNECT", "action": "allow", "path_pattern": "/",
            "endpoint": {"family": 2, "addr": 0, "port": 443},
        }]).to_proc_policy()
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        self.assertEqual(modes[(CLASS_IDS["NETWORK"], OP_IDS[("NETWORK", "CONNECT")])], 2,
                         "ENFORCED fine-grained policy must be mode 2")
        self.assertEqual(len(pp["network"]), 1)
        self.assertEqual(pp["network"][0]["allow"], 1)
        self.assertEqual(pp["network"][0]["port"], 443)

    def test_enforced_operation_wide_allow_is_mode_one(self):
        """ENFORCED operation allow (no endpoint) -> only that operation mode 1."""
        pp = PolicyIR.from_allowed_ops([{
            "event_type": "CONNECT", "action": "allow", "path_pattern": "/",
        }]).to_proc_policy()
        modes = {(c["effect_class"], c["operation"]): c["mode"] for c in pp["classes"]}
        self.assertEqual(modes[(CLASS_IDS["NETWORK"], OP_IDS[("NETWORK", "CONNECT")])], 1)
        self.assertNotIn((CLASS_IDS["NETWORK"], OP_IDS[("NETWORK", "BIND")]), modes)
        self.assertEqual(pp["network"], [])


# ═══════════════════════════════════════════════════════════════
# 5. Full effect-coverage matrix (P1-11)
# ═══════════════════════════════════════════════════════════════

EFFECT_MATRIX = [
    # filesystem effects observed/enforced by ShadowObserve.
    ("file open/read", "OPEN", "FILESYSTEM", "READ", None, None),
    ("file write", "WRITE", "FILESYSTEM", "WRITE", None, None),
    ("file create", "CREATE", "FILESYSTEM", "CREATE", None, None),
    ("file delete", "DELETE", "FILESYSTEM", "DELETE", None, None),
    ("file rename", "RENAME", "FILESYSTEM", "RENAME", None, None),
    ("hard link", "LINK", "FILESYSTEM", "LINK", None, None),
    ("symlink", "SYMLINK", "FILESYSTEM", "SYMLINK", None, None),
    ("truncate", "TRUNCATE", "FILESYSTEM", "TRUNCATE", None, None),
    ("chmod", "CHMOD", "FILESYSTEM", "CHMOD", None, None),
    ("chown", "CHOWN", "FILESYSTEM", "CHOWN", None, None),
    ("mkdir", "MKDIR", "FILESYSTEM", "MKDIR", None, None),
    ("rmdir", "RMDIR", "FILESYSTEM", "RMDIR", None, None),
    # network effects.
    ("tcp connect", "CONNECT", "NETWORK", "CONNECT",
     {"family": 2, "addr": 0x7F000001, "port": 443}, "network"),
    ("bind/listen", "BIND", "NETWORK", "BIND",
     {"family": 2, "addr": 0, "port": 8080}, "network"),
    ("udp send", "SEND", "NETWORK", "SEND",
     {"family": 2, "addr": 0x08080808, "port": 53}, "network"),
    # IPC effects.
    ("pipe write", "PIPE_WRITE", "IPC", "PIPE_WRITE", None, None),
    ("unix socket write", "UNIX_WRITE", "IPC", "UNIX_WRITE", None, None),
    ("sysv shm", "SHM", "IPC", "SYSV_SHM",
     {"ipc_type": "SHM", "target": 11}, "ipc"),
    ("sysv msg", "MSG", "IPC", "SYSV_MSG",
     {"ipc_type": "MSG", "target": 12}, "ipc"),
    ("sysv sem", "SEM", "IPC", "SYSV_SEM",
     {"ipc_type": "SEM", "target": 13}, "ipc"),
    ("posix mqueue", "MQ", "IPC", "POSIX_MQ",
     {"ipc_type": "MQ", "target": 14}, "ipc"),
    ("shared mmap", "SHARED_MAPPING", "IPC", "SHARED_MAPPING",
     {"ipc_type": "MMAP", "target": 15}, "ipc"),
    # signal/process-control effects.
    ("kill/tkill/pidfd_send_signal", "KILL", "SIGNAL", "KILL",
     {"target_cgroup": 9001}, "signal"),
    ("ptrace", "PTRACE", "SIGNAL", "PTRACE",
     {"target_cgroup": 9002}, "signal"),
    # privilege-changing effects.
    ("exec privileged", "EXEC_PRIV", "PRIVILEGE", "EXEC_PRIV", None, None),
    ("setuid", "SETUID", "PRIVILEGE", "SETUID", None, None),
    ("setgid", "SETGID", "PRIVILEGE", "SETGID", None, None),
    ("setgroups", "SETGROUPS", "PRIVILEGE", "SETGROUPS", None, None),
    ("capset", "CAPSET", "PRIVILEGE", "CAPSET", None, None),
    # output effects.
    ("stdout/stderr write", "WRITE_OUT", "OUTPUT", "WRITE_OUT", None, None),
    ("sendfile output", "SENDFILE", "OUTPUT", "SENDFILE", None, None),
    ("splice output", "SPLICE", "OUTPUT", "SPLICE", None, None),
    ("io_uring output", "IO_URING", "OUTPUT", "IO_URING", None, None),
    # system/kernel-control effects: dangerous interfaces must be individually
    # addressable by operation. ENFORCED defaults to deny unless the matching
    # SYSTEM operation, not merely the SYSTEM class, is explicitly allowed.
    ("mount", "MOUNT", "SYSTEM", "MOUNT", None, None),
    ("umount", "UMOUNT", "SYSTEM", "MOUNT", None, None),
    ("namespace unshare", "UNSHARE", "SYSTEM", "NAMESPACE", None, None),
    ("namespace setns", "SETNS", "SYSTEM", "NAMESPACE", None, None),
    ("keyctl", "KEYCTL", "SYSTEM", "KEYRING", None, None),
    ("add_key", "ADD_KEY", "SYSTEM", "KEYRING", None, None),
    ("request_key", "REQUEST_KEY", "SYSTEM", "KEYRING", None, None),
    ("bpf syscall", "BPF", "SYSTEM", "BPF", None, None),
    ("perf_event_open", "PERF_EVENT_OPEN", "SYSTEM", "PERF", None, None),
    ("tty device ioctl", "TTY_IOCTL", "SYSTEM", "TTY_IOCTL", None, None),
    ("process_vm_readv", "PROCESS_VM_READV", "SYSTEM", "PROCESS_VM", None, None),
    ("process_vm_writev", "PROCESS_VM_WRITEV", "SYSTEM", "PROCESS_VM", None, None),
]


class TestEffectCoverageMatrix(unittest.TestCase):
    """Matrix coverage for every externally visible effect class/mechanism.

    The unit tests do not execute kernel hooks, but they lock down the contract
    that the kernel-side hooks, unified schema and orchestrator policy compiler
    rely on: each mechanism has an event name, encoded class/op pair, policy
    mode, and release-time enforcement path.
    """

    def _pp(self, event_name, endpoint=None, action="allow"):
        op = {"event_type": event_name, "action": action, "path_pattern": "/"}
        if endpoint is not None:
            op["endpoint"] = endpoint
        return PolicyIR.from_allowed_ops([op]).to_proc_policy()

    def _modes(self, proc_policy):
        return {(c["effect_class"], c["operation"]): c["mode"]
                for c in proc_policy["classes"]}

    def test_schema_has_legacy_name_for_every_matrix_effect(self):
        legacy = SCHEMA["legacy_event_map"]
        for label, event_name, cls_name, op_name, _endpoint, _bucket in EFFECT_MATRIX:
            with self.subTest(effect=label):
                self.assertIn(event_name, legacy)
                self.assertEqual(legacy[event_name]["class"], cls_name)
                self.assertEqual(legacy[event_name]["op"], op_name)

    def test_every_matrix_effect_encodes_to_expected_class_and_op(self):
        for label, event_name, cls_name, op_name, _endpoint, _bucket in EFFECT_MATRIX:
            with self.subTest(effect=label):
                cls, op = decode_event_type(event_name_to_type(event_name))
                self.assertEqual(cls, CLASS_IDS[cls_name])
                self.assertEqual(op, OP_IDS[(cls_name, op_name)])

    def test_every_matrix_effect_compiles_operation_wide_allow(self):
        for label, event_name, cls_name, op_name, _endpoint, _bucket in EFFECT_MATRIX:
            with self.subTest(effect=label):
                pp = self._pp(event_name)
                self.assertEqual(self._modes(pp)[(CLASS_IDS[cls_name], OP_IDS[(cls_name, op_name)])], 1)
                self.assertEqual(pp["network"], [])
                self.assertEqual(pp["ipc"], [])
                self.assertEqual(pp["signal"], [])

    def test_endpoint_capable_effects_compile_to_fine_grained_mode(self):
        for label, event_name, cls_name, op_name, endpoint, bucket in EFFECT_MATRIX:
            if endpoint is None:
                continue
            with self.subTest(effect=label):
                pp = self._pp(event_name, endpoint=endpoint)
                self.assertEqual(self._modes(pp)[(CLASS_IDS[cls_name], OP_IDS[(cls_name, op_name)])], 2)
                self.assertEqual(len(pp[bucket]), 1)
                self.assertEqual(pp[bucket][0]["allow"], 1)

    def test_endpoint_effects_deny_dominates_allow(self):
        for label, event_name, _cls_name, _op_name, endpoint, bucket in EFFECT_MATRIX:
            if endpoint is None:
                continue
            with self.subTest(effect=label):
                allow = {"event_type": event_name, "action": "allow",
                         "path_pattern": "/", "endpoint": endpoint}
                deny = {"event_type": event_name, "action": "deny",
                        "path_pattern": "/", "endpoint": endpoint}
                pp = PolicyIR.from_allowed_ops([allow, deny]).to_proc_policy()
                self.assertEqual(len(pp[bucket]), 1)
                self.assertEqual(pp[bucket][0]["allow"], 0)

    def test_non_endpoint_classes_reject_endpoint_rules_fail_closed(self):
        bad_endpoint = {"family": 2, "addr": 0, "port": 1}
        for label, event_name, cls_name, _op_name, endpoint, _bucket in EFFECT_MATRIX:
            if endpoint is not None or cls_name in ("NETWORK", "IPC", "SIGNAL"):
                continue
            with self.subTest(effect=label):
                with self.assertRaises(ValueError):
                    self._pp(event_name, endpoint=bad_endpoint)

    def test_phase_matrix_policy_forwarding(self):
        for label, event_name, _cls_name, _op_name, endpoint, _bucket in EFFECT_MATRIX:
            with self.subTest(effect=label, phase="speculative"):
                orch = _bare_orch(TestThreePhaseEffectDecisions()._proc_ok(),
                                  TestThreePhaseEffectDecisions()._fs_ok)
                ok, _out = orch._release_proc("/cg-spec")
                self.assertTrue(ok)
                resume = [c for c in orch.proc_client.calls
                          if c["action"] == "continue_by_cgroup"]
                self.assertNotIn("policy", resume[0])

            with self.subTest(effect=label, phase="authorized_pending"):
                orch = _bare_orch(TestThreePhaseEffectDecisions()._proc_ok(),
                                  TestThreePhaseEffectDecisions()._fs_ok)
                ok, _out = orch._release_proc("/cg-auth")
                self.assertTrue(ok)
                resume = [c for c in orch.proc_client.calls
                          if c["action"] == "continue_by_cgroup"]
                self.assertNotIn("policy", resume[0])

            with self.subTest(effect=label, phase="enforced"):
                pp = self._pp(event_name, endpoint=endpoint)
                orch = _bare_orch(TestThreePhaseEffectDecisions()._proc_ok(),
                                  TestThreePhaseEffectDecisions()._fs_ok)
                ok, _out = orch._release_proc("/cg-enf", proc_policy=pp)
                self.assertTrue(ok)
                resume = [c for c in orch.proc_client.calls
                          if c["action"] == "continue_by_cgroup"]
                self.assertEqual(resume[0].get("policy"), pp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
