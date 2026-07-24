# ShadowProc

eBPF-based process fence for speculative execution. ShadowProc freezes a
monitored process at its **first external effect** (network / IPC / signal /
privilege / data-exfil syscall), notifies userspace, and blocks the syscall
(`-ERESTARTSYS`) until the epoch is finalized. On commit the process is fully
released; on reject the pristine baseline is resumed and the speculative
candidate discarded.

Enforcement is **per-epoch**, not per-syscall: once a process is authorized and
released (`allowed_pids == 2`) it runs to completion. Interception is re-armed
at the next epoch boundary.

## Effect matrix

Each row is a mechanism by which a sandboxed process could produce an
externally-visible / irreversible effect, the hook that covers it, how the
internal-vs-external decision is made, and how an authorized effect is released.

| Effect / mechanism | Hook (`SEC`) | Resource identity | Internal (exempt) vs external (intercept) | Release |
|---|---|---|---|---|
| TCP/UDP/IP connect | `lsm/socket_connect` | `sockaddr` family + addr | AF_INET/INET6 (incl. loopback) intercept; AF_UNSPEC/AF_NETLINK exempt | full release |
| Datagram/stream send | `lsm/socket_sendmsg` | socket family + peer path | AF_UNIX system-socket prefixes exempt; else intercept | full release |
| bind | `lsm/socket_bind` | `sockaddr` family + addr | same classification as connect | full release |
| AF_UNIX connect/send | `lsm/socket_connect` / `sendmsg` | `sun_path` (incl. abstract) | runtime system-socket whitelist exempt; else intercept | full release |
| Exit-hold sentinel | `lsm/socket_connect` | `192.0.2.255:65535` | held until full release (`allowed_pids == 2`) | full release |
| SysV shm | `lsm/shm_alloc_security`, `shm_associate`, `shm_shmat`, `shm_shmctl`, `fmod_ret shmdt` | IPC object | always external (cross-process) | full release |
| POSIX shm (mmap) | `lsm/mmap_file` | file + prot + flags + owning cgroup | writable file-backed `MAP_SHARED` intercept unless positively **same-epoch** (same cgroup already owns the inode); RO or anon exempt; first map fail-closed | full release |
| SysV msg queues | `lsm/msg_queue_*` | IPC object | always external | full release |
| SysV semaphores | `lsm/sem_*` | IPC object | always external | full release |
| POSIX msg queues | `fmod_ret mq_open/mq_timedsend/mq_timedreceive/mq_notify` | mq object | always external | full release |
| Signals to other procs | `lsm/task_kill` | target `task_struct` + cgroup id | same thread-group / same **cgroup (epoch)** exempt; else intercept | full release |
| ptrace | `lsm/ptrace_access_check` | target task | always external | full release |
| Pipe/socket write | `fmod_ret __x64_sys_write`, `writev` | fd → inode `i_mode` | FIFO/socket intercept; regular file exempt; **un-inspectable fd fails closed** | full release |
| Zero-copy exfil | `fmod_ret sendfile64`, `splice`, `vmsplice`, `tee` | (no byte inspection) | **default-deny** while armed (frozen at first use) | full release |
| Async I/O (io_uring) | `fmod_ret io_uring_setup`, `io_uring_enter`, `io_uring_register` | (no SQE inspection) | **default-deny** while armed (frozen at first use) | full release |
| setuid/setgid binary exec | `lsm/bprm_check_security` | inode `S_ISUID`/`S_ISGID` | setuid/setgid binaries intercept | full release |
| UID/GID/groups change | `lsm/task_fix_setuid/setgid/setgroups` | credential change | always intercept | full release |
| capset | `lsm/capset` | capability change | always intercept | full release |

### Fail-closed rules

- **Un-inspectable `write`/`writev` fd** (`fd >= max_fds`, or `fd > 1023` where
  the verifier can no longer bound the fd-table index) is **intercepted**, not
  passed: a high fd may be a pipe/socket carrying data out.
- **`sendfile`/`splice`/`vmsplice`/`tee`** are **default-deny** while a process
  is armed. They move bytes/pages between fds in-kernel and bypass the
  `write`/`sendmsg` hooks, so they are frozen at first use rather than inspected.
- A failed `SIGSTOP` (`bpf_send_signal`) drops the stopped mark and returns
  `-ERESTARTSYS`, so interception re-arms and the syscall is retried.
- `stopped_pids` / `allowed_pids` map-update failure leaves interception armed
  for the overflow tgid (the effect is not silently passed).

### Default-deny / unsupported mechanisms

Any mechanism **not** in the matrix above is not individually classified. Where
a syscall that can move data out is reachable but un-inspectable, the fence
fails closed (see the `write`/`sendfile`/`io_uring` rows). The following are
explicitly **out of scope** for the current fence and are deferred hardening:

- `AF_NETLINK` / D-Bus fine-grained admission (currently exempt as kernel/system peers).
- io_uring SQE-level inspection (currently whole-syscall default-deny).
- Reclaiming `shared_map_owner` entries on last-unmap / inode-free (a reused
  inode pointer could carry a stale owner; the first map is always fail-closed).
- UID/GID drop, capability drop, and mount-namespace isolation for the daemons
  (this pass adds `no_new_privs` + cgroupfs-path confinement only).
