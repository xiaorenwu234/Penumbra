/* SPDX-License-Identifier: MIT */
/*
 * test_audit_log_brackets.cpp -- regression test for the observer's log
 * brackets (the {"type":"header"} / {"type":"end"} metadata records).
 *
 * The bug: AuditEngine::audit() evaluated EVERY parsable line as an event, so
 * the two metadata records the observer writes around each epoch log were
 * audited as effects with event_type 0 ("UNKNOWN") and an empty path. Under a
 * wildcard policy they were silently allowed; under a typed policy (e.g. "allow
 * the twelve FILESYSTEM operations") they became default-deny violations, so a
 * clean epoch was rejected: `DENY: UNKNOWN '' (pid=0 comm=) -- no matching
 * allow rule`. The brackets describe the log, not an operation the epoch
 * performed, so they must be skipped and not counted as events.
 *
 * Fail-closed is preserved: a record with an UNKNOWN "type" value is still
 * audited as an event, and an unparsable record still marks the log incomplete.
 *
 * Self-contained: build with
 *   g++ -std=c++17 -Iinclude -Ibpf tests/test_audit_log_brackets.cpp \
 *       src/audit_engine.cpp -o build/test_audit_log_brackets
 */
#include "ghostbpf-observ/audit_engine.h"
#include "observ_common.h"

#include <cstdio>
#include <fstream>
#include <string>

using namespace ghostbpf_observ;

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

static std::string write_log(const std::string &body) {
    const std::string path = "test_audit_log_brackets.jsonl";
    std::ofstream f(path, std::ios::trunc);
    f << body;
    f.close();
    return path;
}

/* The observer's real bracket records (observer.cpp start()/stop()). */
static const char *HEADER =
    "{\"type\":\"header\",\"epoch_id\":\"ep-1bbbc324e8ce\",\"cgroup_id\":57257}\n";
static const char *END =
    "{\"type\":\"end\",\"end_seq\":2,\"total_events\":2,"
    "\"digest\":\"9a03f2c41b7e8d55\"}\n";

/* One real event line, as evt_to_json() writes it. */
static std::string event_line(const char *event, const std::string &path) {
    return std::string("{\"ts\":1788772109000000000,\"pid\":182487,\"tid\":182487,")
         + "\"uid\":0,\"gid\":0,\"cgroup_id\":57257,\"seq\":1,\"event\":\"" + event
         + "\",\"source\":0,\"arg1\":577,\"arg2\":0,\"arg3\":0,\"comm\":\"bash\","
         + "\"path\":\"" + path + "\",\"new_path\":\"\"}\n";
}

/* exp2's allow_all_fs(): every FILESYSTEM operation, no wildcard, so
 * lifecycle/unknown effects are default-denied. The prefix is path-scoped
 * (not "/") on purpose: an event whose path failed to parse (empty) then
 * matches nothing, so this engine also guards path extraction. */
static AuditEngine fs_only_engine() {
    static const int fs_ops[] = {
        FS_EVENT_OPEN, FS_EVENT_WRITE, FS_EVENT_CREATE, FS_EVENT_DELETE,
        FS_EVENT_RENAME, FS_EVENT_LINK, FS_EVENT_SYMLINK, FS_EVENT_TRUNCATE,
        FS_EVENT_CHMOD, FS_EVENT_CHOWN, FS_EVENT_MKDIR, FS_EVENT_RMDIR,
    };
    AuditEngine e;
    for (int op : fs_ops)
        e.add_allow_rule(op, "/work");
    return e;
}

int main() {
    /* 1. A log holding ONLY the brackets carries no effect at all: under a
     *    typed (non-wildcard) policy it must audit clean, not as two UNKNOWN
     *    violations. (exp2's denyconnect epoch: fenced connect never reached
     *    the kernel, so its sealed log was brackets-only.) */
    {
        auto e = fs_only_engine();
        auto rep = e.audit(write_log(std::string(HEADER) + END));
        CHECK(rep.complete, "brackets-only: log parses cleanly");
        CHECK(rep.total_events == 0, "brackets-only: brackets are not events");
        CHECK(rep.total_violations == 0,
              "brackets-only: no default-deny violation for metadata records");
    }

    /* 2. Brackets around real FILESYSTEM events: the events are still audited
     *    and still counted, the brackets are not. */
    {
        auto e = fs_only_engine();
        auto rep = e.audit(write_log(std::string(HEADER)
                                     + event_line("CREATE", "/work/a.txt")
                                     + event_line("WRITE", "/work/a.txt")
                                     + END));
        CHECK(rep.complete, "bracketed events: log parses cleanly");
        CHECK(rep.total_events == 2, "bracketed events: only real events counted");
        CHECK(rep.total_violations == 0,
              "bracketed events: allowed FILESYSTEM effects pass "
              "(paths parsed and matched against the /work prefix)");
    }

    /* 3. The exp2 reject policy (wildcard allow + WRITE deny on the target):
     *    the denied write is the ONLY violation -- the brackets must not add
     *    noise, and must not hide it. */
    {
        AuditEngine e;
        e.add_allow_rule(-1, "/");
        e.add_deny_rule(FS_EVENT_WRITE, "/work/secret.txt");
        auto rep = e.audit(write_log(std::string(HEADER)
                                     + event_line("WRITE", "/work/secret.txt")
                                     + END));
        CHECK(rep.total_events == 1, "deny policy: one event audited");
        CHECK(rep.total_violations == 1,
              "deny policy: the denied WRITE is reported");
    }

    /* 4. Fail-closed is preserved: an unknown record type is NOT a known
     *    bracket, so it stays an event (here: a default-deny violation under a
     *    typed policy) instead of being skipped. */
    {
        auto e = fs_only_engine();
        auto rep = e.audit(write_log(
            std::string(HEADER)
            + "{\"type\":\"checkpoint\",\"note\":\"not a bracket\"}\n" + END));
        CHECK(rep.total_events == 1, "unknown type: still counted as an event");
        CHECK(rep.total_violations == 1,
              "unknown type: still audited fail-closed (default-deny)");
    }

    /* 5. An unparsable record still marks the log incomplete. */
    {
        auto e = fs_only_engine();
        auto rep = e.audit(write_log(std::string(HEADER) + "{not json\n" + END));
        CHECK(!rep.complete, "unparsable record: log is incomplete");
        CHECK(rep.parse_errors == 1, "unparsable record: counted as a parse error");
    }

    if (failures) {
        fprintf(stderr, "\n%d CHECK(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nALL AUDIT LOG-BRACKET CHECKS PASSED\n");
    return 0;
}
