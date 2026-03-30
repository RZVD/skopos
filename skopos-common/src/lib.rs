#![no_std]

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EventType {
    ProcessExec = 0,
    ProcessExit = 1,
    FileOpen = 2,
    FileCreate = 3,
    FileDelete = 4,
    FileRename = 5,
    NetConnect = 6,
    NetAccept = 7,
    NetBind = 8,
    ProcessFork = 9,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub filename: [u8; 512],
    pub args: [u8; 1024],
    pub envs: [u8; 4096],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub exit_code: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub path: [u8; 512],
    pub flags: i32,
    pub mode: u32,
}

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum NetFamily {
    None = 0,
    AfInet = 2,
    AfInet6 = 10,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum NetProto {
    None = 0,
    IprotoTcp = 6,
    IprotoUdp = 17,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
    pub family: u16,        // AF_INET=2, AF_INET6=10
    pub proto: u16,         // IPPROTO_TCP=6, IPPROTO_UDP=17
    pub pad: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_addr4: u32,
    pub dst_addr4: u32,
    pub src_addr6: [u8; 16],
    pub dst_addr6: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union EventData {
    pub exec: ExecEvent,
    pub exit: ExitEvent,
    pub file: FileEvent,
    pub net: NetEvent,
    pub fork: ForkEvent,
    // pad to fixed size so SensorEvent is always the same size in the ring buffer
    pub _pad: [u8; 5632],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SensorEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub data: EventData,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    pub child_pid: u32,
    pub child_comm: [u8; 16],
}
