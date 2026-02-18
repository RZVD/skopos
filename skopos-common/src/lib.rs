#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
    pub args: [u8; 512],
    pub envs: [u8; 512],
}
