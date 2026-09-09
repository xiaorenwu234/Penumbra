#!/usr/bin/env python3
"""Unit tests for the SessionProxy rc-marker stripping protocol.

SessionProxy.run() delimits one command's output by feeding

    <command>
    echo __SHADOW_RC_<sentinel>__$?
    echo <sentinel>

and then removes the rc-marker line from everything read before the sentinel.
That works while the command's output ends with a newline. When it does NOT
(`printf 'X'`, or `cat` on a file whose last byte is not \\n) the marker is
glued onto the command's last output line, and a prefix-only match then

  * leaks the marker text into the returned output, and
  * reports rc = 0 for a command that actually failed.

Both are silent: the caller sees plausible output and a successful exit. These
tests pin the corrected behaviour (search for the marker, split the line) and
are pure -- no root, no bash, no live services.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from session_proxy import SessionProxy

MARKER = "__SHADOW_RC___SHADOW_DONE_7__"


def strip(lines):
    """Run the parser over a copy, return (output_text, rc)."""
    buf = list(lines)
    rc = SessionProxy._extract_rc(buf, MARKER)
    return "\n".join(buf), rc


class TestMarkerOnItsOwnLine(unittest.TestCase):
    """The well-formed case: output ends with a newline."""

    def test_success_is_removed_and_reports_zero(self):
        out, rc = strip(["hello", "world", f"{MARKER}0"])
        self.assertEqual(out, "hello\nworld")
        self.assertEqual(rc, 0)

    def test_nonzero_exit_status_is_reported(self):
        out, rc = strip(["partial", f"{MARKER}3"])
        self.assertEqual(out, "partial")
        self.assertEqual(rc, 3)

    def test_empty_output(self):
        out, rc = strip([f"{MARKER}0"])
        self.assertEqual(out, "")
        self.assertEqual(rc, 0)

    def test_marker_with_no_digits_defaults_to_zero(self):
        out, rc = strip(["x", MARKER])
        self.assertEqual(out, "x")
        self.assertEqual(rc, 0)

    def test_unparseable_status_defaults_to_zero(self):
        out, rc = strip(["x", f"{MARKER}not-a-number"])
        self.assertEqual(out, "x")
        self.assertEqual(rc, 0)

    def test_no_marker_leaves_output_untouched(self):
        out, rc = strip(["plain", "output"])
        self.assertEqual(out, "plain\noutput")
        self.assertEqual(rc, 0)


class TestMarkerGluedToLastLine(unittest.TestCase):
    """The regression case: the command's output had no trailing newline."""

    def test_content_is_preserved_verbatim(self):
        # exp3 file-offset-restoration: `cat` of a 20-byte file with no \n.
        out, rc = strip([f"AAAAABBBBBCCCCCDDDDD{MARKER}0"])
        self.assertEqual(out, "AAAAABBBBBCCCCCDDDDD")
        self.assertEqual(rc, 0)

    def test_glued_nonzero_status_is_not_lost(self):
        """A failed command must NOT be reported as rc=0 just because its last
        output line lacked a newline."""
        out, rc = strip([f"AAAAABBBBB{MARKER}2"])
        self.assertEqual(out, "AAAAABBBBB")
        self.assertEqual(rc, 2)

    def test_earlier_lines_are_untouched(self):
        out, rc = strip(["first", "second", f"tail-without-newline{MARKER}1"])
        self.assertEqual(out, "first\nsecond\ntail-without-newline")
        self.assertEqual(rc, 1)

    def test_marker_text_never_reaches_the_caller(self):
        out, _rc = strip([f"DATA{MARKER}0"])
        self.assertNotIn("__SHADOW", out)

    def test_content_that_legitimately_contains_the_prefix(self):
        """Only the exact randomized marker is split; ordinary text is kept."""
        out, rc = strip(["echo __SHADOW_RC_ is a marker", f"{MARKER}0"])
        self.assertEqual(out, "echo __SHADOW_RC_ is a marker")
        self.assertEqual(rc, 0)

    def test_only_the_first_marker_occurrence_is_consumed(self):
        out, rc = strip([f"a{MARKER}5", f"b{MARKER}6"])
        self.assertEqual(rc, 5)
        self.assertEqual(out.splitlines()[0], "a")
        # The second line is left as-is: one command yields one status.
        self.assertIn(MARKER, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
