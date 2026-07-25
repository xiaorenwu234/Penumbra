#!/usr/bin/env python3
"""Recovery-envelope regression tests for persistent speculative sessions.

These tests are intentionally pure unit tests: they mock /proc and ShadowProc so
CI can verify the fail-closed invariants without requiring BPF, cgroups, or
root privileges.
"""

import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from session_proxy import (  # noqa: E402
    FdRestoreError,
    FdSnapshot,
    NotAdmissibleError,
    PendingSignalError,
    SessionProxy,
    _Session,
)


class _FakeClient:
    def __init__(self):
        self.calls = []

    def call(self, action, **fields):
        self.calls.append((action, fields))
        if action == "reject_pid":
            return {"status": "ok", "pids": [fields["pid"]]}
        return {"status": "ok"}


class TestRecoveryEnvelope(unittest.TestCase):
    def _proxy(self):
        proxy = SessionProxy.__new__(SessionProxy)
        proxy.client = _FakeClient()
        proxy.verbose = False
        proxy.sessions = {}
        proxy._log = lambda _msg: None
        return proxy

    def test_admission_rejects_pending_signals_before_fork(self):
        proxy = self._proxy()

        def fake_listdir(path):
            if path == "/proc/123/task":
                return ["123"]
            if path == "/proc/123/fd":
                return ["0", "1", "2"]
            raise AssertionError(f"unexpected listdir: {path}")

        def fake_open(path, *args, **kwargs):
            if path == "/proc/123/task/123/children":
                return io.StringIO("")
            if path == "/proc/123/maps":
                return io.StringIO("")
            if path == "/proc/123/status":
                return io.StringIO("State:\tS\nSigPnd:\t0000000000000002\nShdPnd:\t0000000000000000\n")
            raise AssertionError(f"unexpected open: {path}")

        with mock.patch("os.listdir", side_effect=fake_listdir), \
             mock.patch("builtins.open", side_effect=fake_open):
            with self.assertRaisesRegex(NotAdmissibleError, "pending signals"):
                proxy._admit_for_versioning(123)

    def test_reject_fails_closed_when_pending_signal_remains(self):
        proxy = self._proxy()
        sess = _Session("sid", "cg", "/tmp")
        sess.live_pid = 100
        sess.epoch = {"baseline": 100, "candidate": 200, "fd_snapshots": []}
        sess.epoch_buffer = ["speculative output"]
        proxy.sessions["sid"] = sess

        with mock.patch.object(proxy, "_quiesce_epoch"), \
             mock.patch.object(proxy, "_kill_descendants"), \
             mock.patch.object(proxy, "_reap"), \
             mock.patch.object(proxy, "_restore_fds"), \
             mock.patch.object(proxy, "_clear_pending_signals", side_effect=PendingSignalError("pending")):
            with self.assertRaises(PendingSignalError):
                proxy.reject("sid")

        self.assertEqual(sess.live_pid, 100)
        self.assertIsNone(sess.epoch)
        self.assertEqual(sess.epoch_buffer, ["speculative output"])

    def test_clear_pending_signals_fails_closed_on_pending_bits(self):
        proxy = self._proxy()

        def fake_open(path, *args, **kwargs):
            self.assertEqual(path, "/proc/123/status")
            return io.StringIO("SigPnd:\t0000000000000000\nShdPnd:\t0000000000000004\n")

        with mock.patch("builtins.open", side_effect=fake_open):
            with self.assertRaisesRegex(PendingSignalError, "ShdPnd"):
                proxy._clear_pending_signals(123)

    def test_clear_pending_signals_fails_closed_when_proc_unreadable(self):
        proxy = self._proxy()
        with mock.patch("builtins.open", side_effect=OSError("gone")):
            with self.assertRaisesRegex(PendingSignalError, "cannot verify"):
                proxy._clear_pending_signals(123)

    def test_clear_pending_signals_accepts_clean_status(self):
        proxy = self._proxy()

        def fake_open(path, *args, **kwargs):
            self.assertEqual(path, "/proc/123/status")
            return io.StringIO("SigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n")

        with mock.patch("builtins.open", side_effect=fake_open):
            proxy._clear_pending_signals(123)

    def test_fd_restore_fails_closed_when_fd_vanished(self):
        proxy = self._proxy()
        pidfd = os.open("/dev/null", os.O_RDONLY)
        snap = FdSnapshot(fd=4, dev=10, ino=20, offset=0, flags=0)

        def fake_stat(path):
            self.assertEqual(path, "/proc/123/fd/4")
            raise FileNotFoundError(path)

        with mock.patch("session_proxy._pidfd_open", return_value=pidfd), \
             mock.patch("os.stat", side_effect=fake_stat):
            with self.assertRaisesRegex(FdRestoreError, "closed by candidate"):
                proxy._restore_fds(123, [snap])


if __name__ == "__main__":
    unittest.main(verbosity=2)
