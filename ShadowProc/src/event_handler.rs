use std::fmt;

use crate::policy_generated::{encode_event_type, CLASS_NETWORK, OP_CONNECT};

/// Event received from the eBPF ring buffer, matching the kernel-side struct
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InterceptEvent {
    pub pid: u32,
    pub tgid: u32,
    pub syscall_nr: u32,
    pub event_type: u32,
    pub timestamp: u64,
    pub cgroup_id: u64,
    /// Kernel decision that produced this event: 0=ALLOW/info, 1=FENCE,
    /// 2=DENY. ENFORCED denials are reported without SIGSTOP so the
    /// orchestrator can audit EPERM decisions instead of silently losing them.
    pub decision: u8,
    pub _pad0: [u8; 7],
    pub comm: [u8; 16],
}

/// Human-readable event type
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EventType {
    Network,
    Ipc,
    WriteOutput,
    Signal,
    Ptrace,
    PipeWrite,
    Fork,
    ExitHold,
    PrivExec,
    PrivSetuid,
    System,
    Unknown,
}

impl From<u32> for EventType {
    fn from(val: u32) -> Self {
        // FORK is a process lifecycle event (legacy_unmapped=101), not an
        // auditable effect, so it is handled before the (class|op<<8) decode.
        if val == 101 {
            return EventType::Fork;
        }
        let cls = (val & 0xFF) as u8;
        let op = ((val >> 8) & 0xFF) as u8;
        match cls {
            2 => EventType::Network, // EFFECT_CLASS_NETWORK (incl. EXIT_HOLD sentinel; see is_exit_hold)
            3 => EventType::Ipc,
            6 => EventType::WriteOutput,
            4 => match op {
                1 => EventType::Signal, // OP_KILL
                2 => EventType::Ptrace, // OP_PTRACE
                _ => EventType::Unknown,
            },
            5 => match op {
                1 => EventType::PrivExec,   // OP_EXEC_PRIV
                _ => EventType::PrivSetuid, // OP_SETUID/SETGID/SETGROUPS/CAPSET
            },
            7 => EventType::System,
            _ => EventType::Unknown,
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::Network => write!(f, "NETWORK"),
            EventType::Ipc => write!(f, "IPC"),
            EventType::WriteOutput => write!(f, "STDOUT/STDERR"),
            EventType::Signal => write!(f, "SIGNAL"),
            EventType::Ptrace => write!(f, "PTRACE"),
            EventType::PipeWrite => write!(f, "PIPE/FIFO"),
            EventType::Fork => write!(f, "FORK"),
            EventType::ExitHold => write!(f, "EXIT_HOLD"),
            EventType::PrivExec => write!(f, "PRIV_EXEC"),
            EventType::PrivSetuid => write!(f, "PRIV_SETUID"),
            EventType::System => write!(f, "SYSTEM"),
            EventType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Kernel decision encoded in InterceptEvent::decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Fence,
    Deny,
    Unknown(u8),
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Fence => write!(f, "FENCE"),
            Decision::Deny => write!(f, "DENY"),
            Decision::Unknown(v) => write!(f, "UNKNOWN({})", v),
        }
    }
}

impl InterceptEvent {
    /// Get the process name as a string
    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|&c| c == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).to_string()
    }

    /// Create a dummy event for active freeze (not triggered by eBPF interception)
    pub fn dummy_freeze(pid: u32) -> Self {
        InterceptEvent {
            pid,
            tgid: pid,
            syscall_nr: 0,
            event_type: 0, // Unknown - active freeze
            timestamp: 0,
            cgroup_id: 0,
            decision: 1,
            _pad0: [0u8; 7],
            comm: [0u8; 16],
        }
    }

    /// Decode the kernel decision byte.
    pub fn decision_enum(&self) -> Decision {
        match self.decision {
            0 => Decision::Allow,
            1 => Decision::Fence,
            2 => Decision::Deny,
            v => Decision::Unknown(v),
        }
    }

    /// Get the event type enum. ExitHold is detected first because it
    /// reuses the NETWORK/CONNECT encoding (distinguished by syscall_nr).
    pub fn event_type_enum(&self) -> EventType {
        if self.is_exit_hold() {
            return EventType::ExitHold;
        }
        EventType::from(self.event_type)
    }

    /// EXIT_HOLD sentinel: a cooperative connect() to 192.0.2.255:65535 from
    /// libexithold.so signalling process completion. It reuses the
    /// NETWORK/CONNECT event_type encoding; syscall_nr==231 (exit_group)
    /// distinguishes it from a real connect (syscall_nr==42).
    pub fn is_exit_hold(&self) -> bool {
        self.event_type == encode_event_type(CLASS_NETWORK, OP_CONNECT) as u32
            && self.syscall_nr == 231
    }

    /// Get syscall name
    pub fn syscall_name(&self) -> &'static str {
        match self.syscall_nr {
            1 => "write",
            9 => "mmap",
            20 => "writev",
            42 => "connect",
            44 => "sendto",
            46 => "sendmsg",
            49 => "bind",
            50 => "listen",
            288 => "accept4",
            29 => "shmget",
            30 => "shmat",
            31 => "shmctl",
            67 => "shmdt",
            64 => "semget",
            65 => "semop",
            66 => "semctl",
            220 => "semtimedop",
            68 => "msgget",
            69 => "msgsnd",
            70 => "msgrcv",
            71 => "msgctl",
            240 => "mq_open",
            242 => "mq_timedsend",
            243 => "mq_timedreceive",
            244 => "mq_notify",
            62 => "kill",
            200 => "tkill",
            234 => "tgkill",
            59 => "execve",
            101 => "ptrace",
            105 => "setuid",
            106 => "setgid",
            116 => "setgroups",
            126 => "capset",
            165 => "mount",
            166 => "umount2",
            248 => "add_key",
            249 => "request_key",
            250 => "keyctl",
            272 => "unshare",
            298 => "perf_event_open",
            308 => "setns",
            310 => "process_vm_readv",
            311 => "process_vm_writev",
            321 => "bpf",
            16 => "ioctl",
            231 => "exit_group",
            _ => {
                // For fork events, syscall_nr stores parent tgid
                if self.event_type == 101 {
                    "fork"
                } else {
                    "unknown"
                }
            }
        }
    }

    /// For fork events: get the parent tgid (stored in syscall_nr field)
    pub fn parent_tgid(&self) -> Option<u32> {
        if self.event_type == 101 {
            Some(self.syscall_nr)
        } else {
            None
        }
    }
}

impl fmt::Display for InterceptEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}:{}] PID={} TGID={} COMM={} SYSCALL={}({})",
            self.event_type_enum(),
            self.decision_enum(),
            self.pid,
            self.tgid,
            self.comm_str(),
            self.syscall_name(),
            self.syscall_nr,
        )
    }
}
