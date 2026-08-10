/* SPDX-License-Identifier: MIT */
/*
 * test_dual_path_audit.cpp -- regression test for dual-resource (rename / hard
 * link) audit semantics.
 *
 * The bug: the audit engine matched only event.path, so a file in an ALLOWED
 * directory could be renamed/linked INTO a FORBIDDEN directory and pass the
 * audit (the enforcer had the mirror bug, only checking one dentry). The fix
 * evaluates BOTH endpoints (source AND destination); a violation on either
 * side is a violation of the whole operation.
 *
 * Self-contained: writes small JSONL logs to a temp file and asserts the
 * AuditReport. Build/run via run_dual_path_audit_test.sh.
 */
#include "ghostbpf-observ/audit_engine.h"
#include "observ_common.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>

using namespace ghostbpf_observ;

static std::string write_log(const std::string &body) {
    std::string path = "/tmp/shadowobserve_dualpath_test.jsonl";
    std::ofstream f(path, std::ios::trunc);
    f << body;
    f.close();
    return path;
}

static int failures = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s\n", msg);                                \
            failures++;                                                        \
        } else {                                                               \
            fprintf(stderr, "ok:   %s\n", msg);                                \
        }                                                                      \
    } while (0)

/* A policy allowing all operations only under /work (default-deny elsewhere). */
static AuditEngine work_only_engine() {
    AuditEngine e;
    e.add_allow_rule(-1, "/work");
    return e;
}

int main() {
    /* 1. RENAME of an allowed file INTO a forbidden dir: source allowed,
     *    destination forbidden -> MUST be a violation (the bypass). */
    {
        auto e = work_only_engine();
        auto log = write_log(
            "{\"event\":\"RENAME\",\"pid\":10,\"comm\":\"a\","
            "\"path\":\"/work/data.txt\",\"new_path\":\"/etc/evil.txt\"}\n");
        auto rep = e.audit(log);
        CHECK(rep.complete, "rename-out: log parses cleanly");
        CHECK(rep.total_violations == 1,
              "rename allowed->forbidden is a violation (destination checked)");
    }

    /* 2. RENAME of a forbidden file OUT into an allowed dir: source forbidden
     *    -> MUST be a violation (source still checked). */
    {
        auto e = work_only_engine();
        auto log = write_log(
            "{\"event\":\"RENAME\",\"pid\":10,\"comm\":\"a\","
            "\"path\":\"/etc/secret\",\"new_path\":\"/work/loot\"}\n");
        auto rep = e.audit(log);
        CHECK(rep.total_violations == 1,
              "rename forbidden->allowed is a violation (source checked)");
    }

    /* 3. RENAME within the allowed dir: BOTH endpoints allowed -> NO violation. */
    {
        auto e = work_only_engine();
        auto log = write_log(
            "{\"event\":\"RENAME\",\"pid\":10,\"comm\":\"a\","
            "\"path\":\"/work/a\",\"new_path\":\"/work/b\"}\n");
        auto rep = e.audit(log);
        CHECK(rep.total_violations == 0,
              "rename allowed->allowed is NOT a violation");
    }

    /* 4. Hard LINK: created link allowed, existing target forbidden -> violation.
     *    (observer records path=created link, new_path=existing target) */
    {
        auto e = work_only_engine();
        auto log = write_log(
            "{\"event\":\"LINK\",\"pid\":10,\"comm\":\"a\","
            "\"path\":\"/work/alias\",\"new_path\":\"/etc/shadow\"}\n");
        auto rep = e.audit(log);
        CHECK(rep.total_violations == 1,
              "hard link to a forbidden target is a violation (target checked)");
    }

    /* 5. Single-path op (OPEN) with only a `path` -- destination logic must not
     *    fire a spurious violation for an allowed path. */
    {
        auto e = work_only_engine();
        auto log = write_log(
            "{\"event\":\"OPEN\",\"pid\":10,\"comm\":\"a\","
            "\"path\":\"/work/f\",\"new_path\":\"\"}\n");
        auto rep = e.audit(log);
        CHECK(rep.total_violations == 0,
              "single-path OPEN under allowed dir is NOT a violation");
    }

    /* 6. Explicit deny on the destination directory: source allowed but the
     *    destination hits a blacklist rule -> violation. */
    {
        AuditEngine e;
        e.add_allow_rule(-1, "");            // allow everything by default
        e.add_deny_rule(FS_EVENT_RENAME, "/etc");
        auto log = write_log(
            "{\"event\":\"RENAME\",\"pid\":10,\"comm\":\"a\","
            "\"path\":\"/work/x\",\"new_path\":\"/etc/x\"}\n");
        auto rep = e.audit(log);
        CHECK(rep.total_violations == 1,
              "explicit deny on rename destination is a violation");
    }

    if (failures) {
        fprintf(stderr, "\n%d CHECK(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nALL DUAL-PATH AUDIT CHECKS PASSED\n");
    return 0;
}
