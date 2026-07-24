/* SPDX-License-Identifier: MIT */
/*
 * observer.h – unified eBPF observer API for file-system + process events.
 */
#ifndef GHOSTBPF_OBSERV_OBSERVER_H
#define GHOSTBPF_OBSERV_OBSERVER_H

#include <cstdint>
#include <memory>
#include <string>

namespace ghostbpf_observ {

/**
 * IntegrityReport – the log-completeness status of one observation epoch,
 * produced by Observer::stop(). If `complete` is false the JSONL log is known
 * to be missing events, and the epoch MUST fail closed (the design guarantees
 * that an incomplete audit log leads to rollback).
 */
struct IntegrityReport {
    bool        complete       = true;   ///< false => log known-incomplete
    uint64_t    dropped_events = 0;      ///< ring-buffer overflow losses (BPF)
    bool        write_error    = false;  ///< a log write/flush failed
    bool        drain_error    = false;  ///< could not drain the ring at stop
    std::string reason;                  ///< summary when !complete
};

/**
 * Observer – attaches eBPF tracepoints to record all file-system and
 * process events to a single JSONL log.
 *
 * Usage:
 *   Observer obs;
 *   obs.start(cgroup_id, "events.jsonl");
 *   obs.poll(100);
 *   obs.stop();
 */
class Observer {
public:
    Observer();
    ~Observer();

    Observer(const Observer &) = delete;
    Observer &operator=(const Observer &) = delete;
    Observer(Observer &&) noexcept;
    Observer &operator=(Observer &&) noexcept;

    /**
     * Start recording for a specific cgroup.
     * @param cgroup_id   cgroup inode number (from /sys/fs/cgroup/...)
     * @param output_path where to write the JSONL event log
     * @return true on success
     */
    bool start(uint64_t cgroup_id, const std::string &output_path);

    /**
     * Stop recording, drain any events still queued in the ring buffer to the
     * log, close the log file, and report the epoch's log-integrity status.
     * @return IntegrityReport; check `.complete` before trusting the log.
     */
    IntegrityReport stop();

    /**
     * Poll the ring buffer for new events.
     * @param timeout_ms  max wait in milliseconds, 0 = non-blocking
     */
    void poll(int timeout_ms = 0);

    /** @return true if currently recording. */
    bool is_running() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ghostbpf_observ

#endif // GHOSTBPF_OBSERV_OBSERVER_H
