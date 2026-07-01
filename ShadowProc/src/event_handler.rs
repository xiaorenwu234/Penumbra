use std::fmt;

/// Event received from the eBPF ring buffer, matching the kernel-side struct
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InterceptEvent {
    pub pid: u32,
    pub tgid: u32,
    pub syscall_nr: u32,
    pub event_type: u32,
    pub timestamp: u64,
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
    Unknown,
}

impl From<u32> for EventType {
    fn from(val: u32) -> Self {
        match val {
            1 => EventType::Network,
            2 => EventType::Ipc,
            3 => EventType::WriteOutput,
            4 => EventType::Signal,
            5 => EventType::Ptrace,
            6 => EventType::PipeWrite,
            7 => EventType::Fork,
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
            EventType::Unknown => write!(f, "UNKNOWN"),
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
            comm: [0u8; 16],
        }
    }

    /// Get the event type enum
    pub fn event_type_enum(&self) -> EventType {
        EventType::from(self.event_type)
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
            64 => "semget",
            68 => "msgget",
            69 => "msgsnd",
            70 => "msgrcv",
            62 => "kill",
            200 => "tkill",
            234 => "tgkill",
            101 => "ptrace",
            _ => {
                // For fork events, syscall_nr stores parent tgid
                if self.event_type == 7 {
                    "fork"
                } else {
                    "unknown"
                }
            }
        }
    }

    /// For fork events: get the parent tgid (stored in syscall_nr field)
    pub fn parent_tgid(&self) -> Option<u32> {
        if self.event_type == 7 {
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
            "[{}] PID={} TGID={} COMM={} SYSCALL={}({})",
            self.event_type_enum(),
            self.pid,
            self.tgid,
            self.comm_str(),
            self.syscall_name(),
            self.syscall_nr,
        )
    }
}
