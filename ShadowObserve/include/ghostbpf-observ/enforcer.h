/* SPDX-License-Identifier: MIT */
/*
 * enforcer.h – public API for whitelist-based eBPF LSM enforcement.
 *
 * After a cgroup's operations pass audit, the Enforcer installs BPF LSM
 * hooks that restrict the cgroup to only perform whitelisted operations.
 */
#ifndef GHOSTBPF_OBSERV_ENFORCER_H
#define GHOSTBPF_OBSERV_ENFORCER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ghostbpf_observ {

/* Maximum path prefix length in whitelist rules (must match BPF side) */
static constexpr int MAX_PREFIX_LEN = 128;

/**
 * A single whitelist rule describing an allowed operation.
 */
struct WhitelistRule {
    uint64_t cgroup_id;
    uint16_t event_type;    /* FS_EVENT_*, or 0xFFFF for "any event" */
    std::string path_prefix; /* prefix to match, empty = match all paths */
};

/**
 * Enforcer – loads and manages the whitelist eBPF LSM program.
 *
 * Usage:
 *   Enforcer enforcer;
 *   enforcer.enable(cgroup_id);
 *   enforcer.add_rule({cgroup_id, FS_EVENT_OPEN, "/tmp/"});
 *   enforcer.add_rule({cgroup_id, FS_EVENT_CREATE, "/tmp/"});
 *   // ... process resumes, restricted to whitelisted operations
 *   enforcer.disable(cgroup_id);  // remove enforcement
 */
class Enforcer {
public:
    Enforcer();
    ~Enforcer();

    Enforcer(const Enforcer &) = delete;
    Enforcer &operator=(const Enforcer &) = delete;
    Enforcer(Enforcer &&) noexcept;
    Enforcer &operator=(Enforcer &&) noexcept;

    /**
     * Enable enforcement for a cgroup.
     * All FS operations by processes in this cgroup will be checked
     * against the whitelist. Unmatched operations return -EPERM.
     */
    bool enable(uint64_t cgroup_id);

    /**
     * Disable enforcement for a cgroup.
     * Removes the cgroup from enforcement and clears all its rules.
     */
    bool disable(uint64_t cgroup_id);

    /**
     * Add a whitelist rule allowing a specific operation.
     * @param rule  The rule specifying what is allowed.
     * @return true on success.
     */
    bool add_rule(const WhitelistRule &rule);

    /**
     * Add multiple whitelist rules at once.
     * @param rules  Vector of rules to add.
     * @return number of rules successfully added.
     */
    size_t add_rules(const std::vector<WhitelistRule> &rules);

    /**
     * Clear all whitelist rules for a specific cgroup.
     */
    bool clear_rules(uint64_t cgroup_id);

    /**
     * Check if enforcement is active for a cgroup.
     */
    bool is_enforcing(uint64_t cgroup_id) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ghostbpf_observ

#endif // GHOSTBPF_OBSERV_ENFORCER_H
