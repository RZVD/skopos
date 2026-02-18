#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, PerfEventArray},
    programs::TracePointContext,
};
use skopos_common::ExecEvent;

#[map]
static EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

#[map]
static HEAP: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn handle_execve(ctx: TracePointContext) -> u32 {
    let event_ptr = HEAP.get_ptr_mut(0);
    if event_ptr.is_none() {
        return 0;
    }
    let event = unsafe { &mut *event_ptr.unwrap() };

    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.uid = bpf_get_current_uid_gid() as u32;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.comm = [0; 16];
    event.filename = [0; 128];
    event.args = [0; 512];
    event.envs = [0; 512];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    // Required to bypass bpf verifier
    unsafe {
        if let Ok(filename_ptr) = ctx.read_at::<*const u8>(16) {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);
        }

        if let Ok(argv_ptr) = ctx.read_at::<*const *const u8>(24) {
            for i in 0..4 {
                if let Ok(arg_ptr) = bpf_probe_read_user(argv_ptr.add(i)) {
                    if arg_ptr.is_null() {
                        break;
                    }

                    let start = i * 128;
                    if start + 128 <= 512 {
                        let dest = &mut event.args[start..start + 128];
                        let _ = bpf_probe_read_user_str_bytes(arg_ptr, dest);
                    }
                } else {
                    break;
                }
            }
        }

        if let Ok(envp_ptr) = ctx.read_at::<*const *const u8>(32) {
            for i in 0..4 {
                if let Ok(env_ptr) = bpf_probe_read_user(envp_ptr.add(i)) {
                    if env_ptr.is_null() {
                        break;
                    }

                    let start = i * 128;
                    if start + 128 <= 512 {
                        let dest = &mut event.envs[start..start + 128];
                        let _ = bpf_probe_read_user_str_bytes(env_ptr, dest);
                    }
                } else {
                    break;
                }
            }
        }

        EVENTS.output(&ctx, event, 0);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
