#![no_std]
#![no_main]

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;

use vmlinux::{dentry, file, linux_binprm, path, task_struct};

use aya_ebpf::EbpfContext;
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_task, bpf_get_current_uid_gid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use skopos_common::{EventType, ExecEvent, FileEvent, NetEvent, SensorEvent};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map]
static HEAP: PerCpuArray<SensorEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static STAGING: LruHashMap<u32, ExecEvent> = LruHashMap::with_max_entries(1024, 0);

#[map]
static PATH_SCRATCH: PerCpuArray<PathScratch> = PerCpuArray::with_max_entries(1, 0);

const MAX_SLOTS: usize = 8;
const MAX_DIR_DEPTH: usize = 7; // MAX_SLOTS - 1, leaves room for filename

#[repr(C)]
pub struct PathScratch {
    pub components: [[u8; 64]; MAX_SLOTS],
    pub count: u32,
}

// manual loop unrolling due to verifier
macro_rules! copy_slot {
    ($out:expr, $scratch:expr, $dst_slot:expr, $src_idx:expr) => {{
        let dst_off = $dst_slot * 64;
        let src = &$scratch.components[$src_idx];
        let src_ptr = src.as_ptr() as *const u64;
        let dst_ptr = $out.as_mut_ptr().add(dst_off) as *mut u64;
        core::ptr::write_unaligned(
            dst_ptr.add(0),
            bpf_probe_read_kernel(src_ptr.add(0)).unwrap_or(0),
        );
        core::ptr::write_unaligned(
            dst_ptr.add(1),
            bpf_probe_read_kernel(src_ptr.add(1)).unwrap_or(0),
        );
        core::ptr::write_unaligned(
            dst_ptr.add(2),
            bpf_probe_read_kernel(src_ptr.add(2)).unwrap_or(0),
        );
        core::ptr::write_unaligned(
            dst_ptr.add(3),
            bpf_probe_read_kernel(src_ptr.add(3)).unwrap_or(0),
        );
        core::ptr::write_unaligned(
            dst_ptr.add(4),
            bpf_probe_read_kernel(src_ptr.add(4)).unwrap_or(0),
        );
        core::ptr::write_unaligned(
            dst_ptr.add(5),
            bpf_probe_read_kernel(src_ptr.add(5)).unwrap_or(0),
        );
        core::ptr::write_unaligned(
            dst_ptr.add(6),
            bpf_probe_read_kernel(src_ptr.add(6)).unwrap_or(0),
        );
        core::ptr::write_unaligned(
            dst_ptr.add(7),
            bpf_probe_read_kernel(src_ptr.add(7)).unwrap_or(0),
        );
    }};
}

macro_rules! write_leaf {
    ($out:expr, $name_ptr:expr, $slot:expr) => {
        match $slot {
            0 => {
                let _ = bpf_probe_read_kernel_str_bytes(
                    $name_ptr,
                    &mut *($out.as_mut_ptr().add(0) as *mut [u8; 64]),
                );
            }
            1 => {
                let _ = bpf_probe_read_kernel_str_bytes(
                    $name_ptr,
                    &mut *($out.as_mut_ptr().add(64) as *mut [u8; 64]),
                );
            }
            2 => {
                let _ = bpf_probe_read_kernel_str_bytes(
                    $name_ptr,
                    &mut *($out.as_mut_ptr().add(128) as *mut [u8; 64]),
                );
            }
            3 => {
                let _ = bpf_probe_read_kernel_str_bytes(
                    $name_ptr,
                    &mut *($out.as_mut_ptr().add(192) as *mut [u8; 64]),
                );
            }
            4 => {
                let _ = bpf_probe_read_kernel_str_bytes(
                    $name_ptr,
                    &mut *($out.as_mut_ptr().add(256) as *mut [u8; 64]),
                );
            }
            5 => {
                let _ = bpf_probe_read_kernel_str_bytes(
                    $name_ptr,
                    &mut *($out.as_mut_ptr().add(320) as *mut [u8; 64]),
                );
            }
            6 => {
                let _ = bpf_probe_read_kernel_str_bytes(
                    $name_ptr,
                    &mut *($out.as_mut_ptr().add(384) as *mut [u8; 64]),
                );
            }
            7 => {
                let _ = bpf_probe_read_kernel_str_bytes(
                    $name_ptr,
                    &mut *($out.as_mut_ptr().add(448) as *mut [u8; 64]),
                );
            }
            _ => {}
        }
    };
}

#[inline(always)]
unsafe fn read_dentry_path(dentry_ptr: *const dentry, out: &mut [u8; 512]) {
    let scratch = match PATH_SCRATCH.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return,
    };

    scratch.count = 0;
    let mut cur = dentry_ptr;

    for i in 0..MAX_DIR_DEPTH {
        if cur.is_null() {
            break;
        }

        let parent = bpf_probe_read_kernel(&(*cur).d_parent as *const *mut dentry)
            .unwrap_or(core::ptr::null_mut()) as *const dentry;

        let name_ptr = bpf_probe_read_kernel(&(*cur).d_name.name as *const *const u8)
            .unwrap_or(core::ptr::null());

        if name_ptr.is_null() {
            break;
        }

        let first = bpf_probe_read_kernel(name_ptr as *const u8).unwrap_or(0);
        let at_root = parent == cur || first == 0;

        scratch.components[i] = [0u8; 64];
        let _ = bpf_probe_read_kernel_str_bytes(name_ptr, &mut scratch.components[i]);

        scratch.count = (i + 1) as u32;
        if at_root {
            break;
        }
        cur = parent;
    }

    let count = scratch.count as usize;
    match count {
        1 => {
            copy_slot!(out, scratch, 0, 0);
        }
        2 => {
            copy_slot!(out, scratch, 0, 1);
            copy_slot!(out, scratch, 1, 0);
        }
        3 => {
            copy_slot!(out, scratch, 0, 2);
            copy_slot!(out, scratch, 1, 1);
            copy_slot!(out, scratch, 2, 0);
        }
        4 => {
            copy_slot!(out, scratch, 0, 3);
            copy_slot!(out, scratch, 1, 2);
            copy_slot!(out, scratch, 2, 1);
            copy_slot!(out, scratch, 3, 0);
        }
        5 => {
            copy_slot!(out, scratch, 0, 4);
            copy_slot!(out, scratch, 1, 3);
            copy_slot!(out, scratch, 2, 2);
            copy_slot!(out, scratch, 3, 1);
            copy_slot!(out, scratch, 4, 0);
        }
        6 => {
            copy_slot!(out, scratch, 0, 5);
            copy_slot!(out, scratch, 1, 4);
            copy_slot!(out, scratch, 2, 3);
            copy_slot!(out, scratch, 3, 2);
            copy_slot!(out, scratch, 4, 1);
            copy_slot!(out, scratch, 5, 0);
        }
        7 => {
            copy_slot!(out, scratch, 0, 6);
            copy_slot!(out, scratch, 1, 5);
            copy_slot!(out, scratch, 2, 4);
            copy_slot!(out, scratch, 3, 3);
            copy_slot!(out, scratch, 4, 2);
            copy_slot!(out, scratch, 5, 1);
            copy_slot!(out, scratch, 6, 0);
        }
        _ => {}
    }
}

#[inline(always)]
unsafe fn read_file_path(file_ptr: *const file, out: &mut [u8; 512]) {
    let path_ptr = &(*file_ptr).f_path as *const path as *mut aya_ebpf::bindings::path;
    let buf_ptr = out.as_mut_ptr() as *mut i8;
    aya_ebpf::helpers::gen::bpf_d_path(path_ptr, buf_ptr, 512);
}

#[inline(always)]
fn get_ppid() -> u32 {
    unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        let parent = bpf_probe_read_kernel(&(*task).real_parent as *const *mut task_struct)
            .unwrap_or(core::ptr::null_mut());
        if parent.is_null() {
            return 0;
        }
        bpf_probe_read_kernel(&(*parent).tgid as *const i32).unwrap_or(0) as u32
    }
}

#[inline(always)]
fn init_heap(event_type: EventType) -> Option<&'static mut SensorEvent> {
    let event = unsafe { &mut *HEAP.get_ptr_mut(0)? };
    event.event_type = event_type;
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.ppid = get_ppid();
    event.uid = bpf_get_current_uid_gid() as u32;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.comm = [0u8; 16];
    if let Ok(c) = bpf_get_current_comm() {
        event.comm = c;
    }
    Some(event)
}

#[inline(always)]
fn emit(event: &SensorEvent) {
    if let Some(mut entry) = EVENTS.reserve::<SensorEvent>(0) {
        entry.write(*event);
        entry.submit(0);
    }
}

#[inline(always)]
unsafe fn fill_args_envs(ctx: &TracePointContext, exec: &mut ExecEvent) {
    if let Ok(argv_ptr) = ctx.read_at::<*const *const u8>(24) {
        for i in 0..8usize {
            if let Ok(arg_ptr) = bpf_probe_read_user(argv_ptr.add(i)) {
                if arg_ptr.is_null() {
                    break;
                }
                let start = i * 128;
                if start + 128 > 1024 {
                    break;
                }
                let _ = bpf_probe_read_user_str_bytes(arg_ptr, &mut exec.args[start..start + 128]);
            } else {
                break;
            }
        }
    }
    if let Ok(envp_ptr) = ctx.read_at::<*const *const u8>(32) {
        for i in 0..32usize {
            if let Ok(env_ptr) = bpf_probe_read_user(envp_ptr.add(i)) {
                if env_ptr.is_null() {
                    break;
                }
                let start = i * 128;
                if start + 128 > 4096 {
                    break;
                }
                let _ = bpf_probe_read_user_str_bytes(env_ptr, &mut exec.envs[start..start + 128]);
            } else {
                break;
            }
        }
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn handle_exec_tp(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let heap = match HEAP.get_ptr_mut(0) {
        Some(p) => unsafe { &mut *p },
        None => return 0,
    };
    let exec = unsafe { &mut heap.data.exec };
    exec.filename = [0u8; 512];
    exec.args = [0u8; 1024];
    exec.envs = [0u8; 4096];
    unsafe {
        if let Ok(filename_ptr) = ctx.read_at::<*const u8>(16) {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut exec.filename);
        }
        fill_args_envs(&ctx, exec);
        STAGING.insert(&pid, exec, 0).ok();
    }
    0
}

#[lsm(hook = "bprm_check_security")]
pub fn handle_exec_lsm(ctx: LsmContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let staged = match STAGING.get_ptr_mut(&pid) {
        Some(e) => unsafe { &mut *e },
        None => return 0,
    };
    unsafe {
        let bprm = ctx.arg::<*const linux_binprm>(0);
        if !bprm.is_null() {
            let filename_ptr = bpf_probe_read_kernel(&(*bprm).filename as *const *const i8)
                .unwrap_or(core::ptr::null()) as *const u8;
            if !filename_ptr.is_null() {
                staged.filename = [0u8; 512];
                let _ = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut staged.filename);
            }
        }
    }
    let event = match init_heap(EventType::ProcessExec) {
        Some(e) => e,
        None => return 0,
    };
    event.data.exec = *staged;
    emit(event);
    STAGING.remove(&pid).ok();
    0
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    let event = match init_heap(EventType::ProcessExit) {
        Some(e) => e,
        None => return 0,
    };
    let exit_code: i32 = unsafe { ctx.read_at::<i32>(16).unwrap_or(0) };
    event.data.exit.exit_code = exit_code;
    emit(event);
    0
}

#[lsm(hook = "file_open")]
pub fn handle_file_open(ctx: LsmContext) -> i32 {
    let event = match init_heap(EventType::FileOpen) {
        Some(e) => e,
        None => return 0,
    };
    unsafe {
        event.data.file = FileEvent {
            path: [0u8; 512],
            flags: 0,
            mode: 0,
        };
        let file_ptr = ctx.arg::<*const file>(0);
        if file_ptr.is_null() {
            return 0;
        }
        read_file_path(file_ptr, &mut event.data.file.path);
    }
    emit(event);
    0
}

#[lsm(hook = "path_mknod")]
pub fn handle_file_create(ctx: LsmContext) -> i32 {
    let event = match init_heap(EventType::FileCreate) {
        Some(e) => e,
        None => return 0,
    };
    unsafe {
        event.data.file = FileEvent {
            path: [0u8; 512],
            flags: 0,
            mode: 0,
        };

        let parent_path = ctx.arg::<*const path>(0);
        if parent_path.is_null() {
            return 0;
        }
        let parent_dentry = bpf_probe_read_kernel(&(*parent_path).dentry as *const *mut dentry)
            .unwrap_or(core::ptr::null_mut()) as *const dentry;
        if parent_dentry.is_null() {
            return 0;
        }

        read_dentry_path(parent_dentry, &mut event.data.file.path);

        let slot = {
            let scratch = match PATH_SCRATCH.get_ptr_mut(0) {
                Some(p) => &*p,
                None => {
                    emit(event);
                    return 0;
                }
            };
            scratch.count as usize
        };
        let new_dentry = ctx.arg::<*const dentry>(1);
        if !new_dentry.is_null() {
            let name_ptr = bpf_probe_read_kernel(&(*new_dentry).d_name.name as *const *const u8)
                .unwrap_or(core::ptr::null());
            if !name_ptr.is_null() {
                write_leaf!(event.data.file.path, name_ptr, slot);
            }
        }
    }
    emit(event);
    0
}

#[lsm(hook = "path_unlink")]
pub fn handle_file_delete(ctx: LsmContext) -> i32 {
    let event = match init_heap(EventType::FileDelete) {
        Some(e) => e,
        None => return 0,
    };
    unsafe {
        event.data.file = FileEvent {
            path: [0u8; 512],
            flags: 0,
            mode: 0,
        };

        let parent_path = ctx.arg::<*const path>(0);
        if parent_path.is_null() {
            return 0;
        }
        let parent_dentry = bpf_probe_read_kernel(&(*parent_path).dentry as *const *mut dentry)
            .unwrap_or(core::ptr::null_mut()) as *const dentry;
        if parent_dentry.is_null() {
            return 0;
        }

        read_dentry_path(parent_dentry, &mut event.data.file.path);

        let slot = {
            let scratch = match PATH_SCRATCH.get_ptr_mut(0) {
                Some(p) => &*p,
                None => {
                    emit(event);
                    return 0;
                }
            };
            scratch.count as usize
        };
        let dentry_ptr = ctx.arg::<*const dentry>(1);
        if !dentry_ptr.is_null() {
            let name_ptr = bpf_probe_read_kernel(&(*dentry_ptr).d_name.name as *const *const u8)
                .unwrap_or(core::ptr::null());
            if !name_ptr.is_null() {
                write_leaf!(event.data.file.path, name_ptr, slot);
            }
        }
    }
    emit(event);
    0
}

#[lsm(hook = "path_rename")]
pub fn handle_file_rename(ctx: LsmContext) -> i32 {
    let event = match init_heap(EventType::FileRename) {
        Some(e) => e,
        None => return 0,
    };
    unsafe {
        event.data.file = FileEvent {
            path: [0u8; 512],
            flags: 0,
            mode: 0,
        };

        let parent_path = ctx.arg::<*const path>(0);
        if parent_path.is_null() {
            return 0;
        }
        let parent_dentry = bpf_probe_read_kernel(&(*parent_path).dentry as *const *mut dentry)
            .unwrap_or(core::ptr::null_mut()) as *const dentry;
        if parent_dentry.is_null() {
            return 0;
        }

        read_dentry_path(parent_dentry, &mut event.data.file.path);

        let slot = {
            let scratch = match PATH_SCRATCH.get_ptr_mut(0) {
                Some(p) => &*p,
                None => {
                    emit(event);
                    return 0;
                }
            };
            scratch.count as usize
        };
        let old_dentry = ctx.arg::<*const dentry>(1);
        if !old_dentry.is_null() {
            let name_ptr = bpf_probe_read_kernel(&(*old_dentry).d_name.name as *const *const u8)
                .unwrap_or(core::ptr::null());
            if !name_ptr.is_null() {
                write_leaf!(event.data.file.path, name_ptr, slot);
            }
        }
    }
    emit(event);
    0
}

#[lsm(hook = "socket_connect")]
pub fn handle_net_connect(ctx: LsmContext) -> i32 {
    let event = match init_heap(EventType::NetConnect) {
        Some(e) => e,
        None => return 0,
    };
    unsafe {
        event.data.net = NetEvent {
            family: 0,
            proto: 0,
            pad: 0,
            src_port: 0,
            dst_port: 0,
            src_addr4: 0,
            dst_addr4: 0,
            src_addr6: [0u8; 16],
            dst_addr6: [0u8; 16],
        };
        let sockaddr = ctx.arg::<*const u8>(1);
        if sockaddr.is_null() {
            return 0;
        }
        let family = bpf_probe_read_kernel(sockaddr as *const u16).unwrap_or(0);
        event.data.net.family = family;
        if family == 2 {
            event.data.net.dst_port =
                u16::from_be(bpf_probe_read_kernel(sockaddr.add(2) as *const u16).unwrap_or(0));
            event.data.net.dst_addr4 =
                bpf_probe_read_kernel(sockaddr.add(4) as *const u32).unwrap_or(0);
        } else if family == 10 {
            event.data.net.dst_port =
                u16::from_be(bpf_probe_read_kernel(sockaddr.add(2) as *const u16).unwrap_or(0));
            for i in 0..16usize {
                event.data.net.dst_addr6[i] =
                    bpf_probe_read_kernel(sockaddr.add(8 + i) as *const u8).unwrap_or(0);
            }
        } else {
            return 0;
        }
    }
    emit(event);
    0
}

#[lsm(hook = "socket_bind")]
pub fn handle_net_bind(ctx: LsmContext) -> i32 {
    let event = match init_heap(EventType::NetBind) {
        Some(e) => e,
        None => return 0,
    };
    unsafe {
        event.data.net = NetEvent {
            family: 0,
            proto: 0,
            pad: 0,
            src_port: 0,
            dst_port: 0,
            src_addr4: 0,
            dst_addr4: 0,
            src_addr6: [0u8; 16],
            dst_addr6: [0u8; 16],
        };
        let sockaddr = ctx.arg::<*const u8>(1);
        if sockaddr.is_null() {
            return 0;
        }
        let family = bpf_probe_read_kernel(sockaddr as *const u16).unwrap_or(0);
        event.data.net.family = family;
        if family == 2 {
            event.data.net.src_port =
                u16::from_be(bpf_probe_read_kernel(sockaddr.add(2) as *const u16).unwrap_or(0));
            event.data.net.src_addr4 =
                bpf_probe_read_kernel(sockaddr.add(4) as *const u32).unwrap_or(0);
        } else if family == 10 {
            event.data.net.src_port =
                u16::from_be(bpf_probe_read_kernel(sockaddr.add(2) as *const u16).unwrap_or(0));
            for i in 0..16usize {
                event.data.net.src_addr6[i] =
                    bpf_probe_read_kernel(sockaddr.add(8 + i) as *const u8).unwrap_or(0);
            }
        } else {
            return 0;
        }
    }
    emit(event);
    0
}

#[lsm(hook = "socket_accept")]
pub fn handle_net_accept(_ctx: LsmContext) -> i32 {
    let event = match init_heap(EventType::NetAccept) {
        Some(e) => e,
        None => return 0,
    };
    event.data.net = NetEvent {
        family: 0,
        proto: 0,
        pad: 0,
        src_port: 0,
        dst_port: 0,
        src_addr4: 0,
        dst_addr4: 0,
        src_addr6: [0u8; 16],
        dst_addr6: [0u8; 16],
    };
    emit(event);
    0
}

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn handle_fork(ctx: TracePointContext) -> u32 {
    let event = match init_heap(EventType::ProcessFork) {
        Some(e) => e,
        None => return 0,
    };
    unsafe {
        let child_pid = ctx.read_at::<u32>(44).unwrap_or(0);
        let child_comm =
            bpf_probe_read_kernel(ctx.as_ptr().add(28) as *const [u8; 16]).unwrap_or([0u8; 16]);
        event.data.fork.child_pid = child_pid;
        event.data.fork.child_comm = child_comm;
    }
    emit(event);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
