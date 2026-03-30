mod es;

use aya::programs::Lsm;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Btf, EbpfLoader};
use dashmap::DashMap;
use env_logger::{Builder, Env};
use es::{EsConfig, SkoposEvent};
use futures::{pin_mut, StreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher::{self, watcher, Event};
use kube::{
    api::{Api, DeleteParams},
    Client as KubeClient,
};
use log::{error, info, warn};
use regex::Regex;
use skopos_common::{EventType, SensorEvent};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::linux::fs::MetadataExt;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc::Sender;
use walkdir::WalkDir;

type CgroupCache = Arc<DashMap<u64, String>>;


fn str_from_bytes(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or("?").trim_matches('\0')
}

fn path_from_slots(bytes: &[u8; 512]) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for slot in 0..8 {
        let off = slot * 64;
        let chunk = &bytes[off..off + 64];
        let end = chunk.iter().position(|&b| b == 0).unwrap_or(64);
        if end == 0 {
            continue;
        }
        let s = std::str::from_utf8(&chunk[..end]).unwrap_or("?");
        if s == "." || s == "/" {
            continue;
        }
        parts.push(s);
    }
    if parts.is_empty() {
        return "/".to_string();
    }
    format!("/{}", parts.join("/"))
}

fn strip_overlay_prefix(path: &str) -> &str {
    for marker in &["/fs/", "/diff/", "/merged/"] {
        if let Some(pos) = path.find(marker) {
            return &path[pos + marker.len() - 1..];
        }
    }
    path
}

fn parse_null_separated(blob: &[u8], max: usize) -> Vec<String> {
    blob[..max.min(blob.len())]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| std::str::from_utf8(s).unwrap_or("?").to_string())
        .collect()
}

fn format_addr(net: &skopos_common::NetEvent) -> String {
    if net.family == 2 {
        format!(
            "{}:{}",
            Ipv4Addr::from(u32::from_be(net.dst_addr4)),
            net.dst_port
        )
    } else if net.family == 10 {
        format!("[{}]:{}", Ipv6Addr::from(net.dst_addr6), net.dst_port)
    } else {
        format!("family:{}", net.family)
    }
}

fn proto_str(proto: u8) -> String {
    match proto {
        6 => "TCP".into(),
        17 => "UDP".into(),
        n => format!("proto:{}", n),
    }
}


async fn kill_pod(client: KubeClient, pod_identity: &str) -> anyhow::Result<()> {
    let parts: Vec<&str> = pod_identity.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid pod identity format: {}",
            pod_identity
        ));
    }
    let (namespace, name) = (parts[0], parts[1]);
    warn!(
        "HEURISTIC TRIGGERED: Terminating pod {} in namespace {}",
        name, namespace
    );
    let pods_api: Api<Pod> = Api::namespaced(client, namespace);
    let dp = DeleteParams {
        grace_period_seconds: Some(0),
        ..Default::default()
    };
    pods_api.delete(name, &dp).await?;
    Ok(())
}

fn extract_pod_uid(path: &str) -> Option<String> {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
        ).unwrap();
    }
    RE.find(path).map(|m| m.as_str().to_string())
}

fn refresh_cache_for_pod(cache: CgroupCache, pod: &Pod) {
    if let (Some(uid), Some(name), Some(ns)) = (
        pod.metadata.uid.as_ref(),
        pod.metadata.name.as_ref(),
        pod.metadata.namespace.as_ref(),
    ) {
        let identity = format!("{}/{}", ns, name);
        let root = "/sys/fs/cgroup/kubepods";
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if entry.path().to_string_lossy().contains(uid.as_str()) {
                if let Ok(meta) = fs::metadata(entry.path()) {
                    cache.insert(meta.st_ino(), identity.clone());
                }
            }
        }
    }
}

fn build_cgroup_cache() -> DashMap<u64, String> {
    let cache = DashMap::new();
    let root = "/sys/fs/cgroup/kubepods";
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if let Ok(metadata) = fs::metadata(entry.path()) {
            let path = entry.path().to_string_lossy();
            if let Some(uid) = extract_pod_uid(&path) {
                cache.insert(metadata.st_ino(), uid);
            }
        }
    }
    cache
}

async fn sync_initial_pods(pods_api: &Api<Pod>, cache: CgroupCache) -> anyhow::Result<()> {
    info!("Syncing pod names with K8s API...");
    let pod_list = pods_api.list(&kube::api::ListParams::default()).await?;
    for pod in pod_list {
        refresh_cache_for_pod(Arc::clone(&cache), &pod);
    }
    Ok(())
}

fn dispatch_event(
    event: &SensorEvent,
    pod_identity: &str,
    tx: &Sender<SkoposEvent>,
) {
    let pod = pod_identity.to_string();

    let skopos_event = match event.event_type {
        EventType::ProcessExec => {
            let exec = unsafe { &event.data.exec };
            let binary = str_from_bytes(&exec.filename).to_string();
            let comm = str_from_bytes(&event.comm).to_string();
            let args = parse_null_separated(&exec.args, 1024);
            let envs = parse_null_separated(&exec.envs, 4096);

            info!(
                "[EXEC]        Pod: {} | PID: {} | PPID: {} | UID: {} | Comm: {} | Bin: {} | Args: {:?}",
                pod, event.pid, event.ppid, event.uid, comm, binary, args
            );

            SkoposEvent::ProcessExec {
                pod,
                pid: event.pid,
                ppid: event.ppid,
                uid: event.uid,
                comm,
                binary,
                args,
                envs,
            }
        }

        EventType::ProcessExit => {
            let exit_code = unsafe { event.data.exit.exit_code };
            let comm = str_from_bytes(&event.comm).to_string();
            info!(
                "[EXIT]        Pod: {} | PID: {} | UID: {} | Comm: {} | ExitCode: {}",
                pod, event.pid, event.uid, comm, exit_code
            );
            SkoposEvent::ProcessExit {
                pod,
                pid: event.pid,
                uid: event.uid,
                comm,
                exit_code,
            }
        }

        EventType::ProcessFork => {
            let fork = unsafe { &event.data.fork };
            let parent_comm = str_from_bytes(&event.comm).to_string();
            let child_comm = str_from_bytes(&fork.child_comm).to_string();
            info!(
                "[FORK]        Pod: {} | PPID: {} | Parent: {} | CPID: {} | Child: {}",
                pod, event.pid, parent_comm, fork.child_pid, child_comm
            );
            SkoposEvent::ProcessFork {
                pod,
                ppid: event.pid,
                parent_comm,
                child_pid: fork.child_pid,
                child_comm,
            }
        }

        EventType::FileOpen => {
            let raw = path_from_slots(unsafe { &event.data.file.path });
            let path = strip_overlay_prefix(&raw).to_string();
            let comm = str_from_bytes(&event.comm).to_string();
            info!(
                "[FILE:OPEN]   Pod: {} | PID: {} | UID: {} | Comm: {} | Path: {}",
                pod, event.pid, event.uid, comm, path
            );
            SkoposEvent::FileOpen { pod, pid: event.pid, uid: event.uid, comm, path }
        }

        EventType::FileCreate => {
            let raw = path_from_slots(unsafe { &event.data.file.path });
            let path = strip_overlay_prefix(&raw).to_string();
            let comm = str_from_bytes(&event.comm).to_string();
            info!(
                "[FILE:CREATE] Pod: {} | PID: {} | UID: {} | Comm: {} | Path: {}",
                pod, event.pid, event.uid, comm, path
            );
            SkoposEvent::FileCreate { pod, pid: event.pid, uid: event.uid, comm, path }
        }

        EventType::FileDelete => {
            let raw = path_from_slots(unsafe { &event.data.file.path });
            let path = strip_overlay_prefix(&raw).to_string();
            let comm = str_from_bytes(&event.comm).to_string();
            info!(
                "[FILE:DELETE] Pod: {} | PID: {} | UID: {} | Comm: {} | Path: {}",
                pod, event.pid, event.uid, comm, path
            );
            SkoposEvent::FileDelete { pod, pid: event.pid, uid: event.uid, comm, path }
        }

        EventType::FileRename => {
            let raw = path_from_slots(unsafe { &event.data.file.path });
            let from = strip_overlay_prefix(&raw).to_string();
            let comm = str_from_bytes(&event.comm).to_string();
            info!(
                "[FILE:RENAME] Pod: {} | PID: {} | UID: {} | Comm: {} | From: {}",
                pod, event.pid, event.uid, comm, from
            );
            SkoposEvent::FileRename { pod, pid: event.pid, uid: event.uid, comm, from }
        }

        EventType::NetConnect => {
            let net = unsafe { &event.data.net };
            let comm = str_from_bytes(&event.comm).to_string();
            let dst = format_addr(net);
            let proto = proto_str(net.proto as u8);
            info!(
                "[NET:CONNECT] Pod: {} | PID: {} | UID: {} | Comm: {} | Dst: {} | Proto: {}",
                pod, event.pid, event.uid, comm, dst, proto
            );
            SkoposEvent::NetConnect { pod, pid: event.pid, uid: event.uid, comm, dst, proto }
        }

        EventType::NetBind => {
            let net = unsafe { &event.data.net };
            let comm = str_from_bytes(&event.comm).to_string();
            let addr = if net.family == 2 {
                format!("{}:{}", Ipv4Addr::from(u32::from_be(net.src_addr4)), net.src_port)
            } else {
                format!("[{}]:{}", Ipv6Addr::from(net.src_addr6), net.src_port)
            };
            let proto = proto_str(net.proto as u8);
            info!(
                "[NET:BIND]    Pod: {} | PID: {} | UID: {} | Comm: {} | Addr: {}",
                pod, event.pid, event.uid, comm, addr
            );
            SkoposEvent::NetBind { pod, pid: event.pid, uid: event.uid, comm, addr, proto }
        }

        EventType::NetAccept => {
            let comm = str_from_bytes(&event.comm).to_string();
            info!(
                "[NET:ACCEPT]  Pod: {} | PID: {} | UID: {} | Comm: {}",
                pod, event.pid, event.uid, comm
            );
            SkoposEvent::NetAccept { pod, pid: event.pid, uid: event.uid, comm }
        }

        // default block. Commented since all previous enum values are exhaustive
        // _ => return,
    };

    if let Err(e) = tx.try_send(skopos_event) {
        warn!("ES shipper channel full, dropping event: {}", e);
    }
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = Env::default().default_filter_or("info");
    Builder::from_env(env).init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    let btf = Btf::from_sys_fs()?;
    let mut bpf = EbpfLoader::new()
        .btf(Some(&btf))
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/skopos")))?;

    let tp: &mut TracePoint = bpf.program_mut("handle_exec_tp").unwrap().try_into()?;
    tp.load()?;
    tp.attach("syscalls", "sys_enter_execve")?;
    info!("Tracepoint 'sys_enter_execve' attached.");

    let exit_tp: &mut TracePoint = bpf.program_mut("handle_exit").unwrap().try_into()?;
    exit_tp.load()?;
    exit_tp.attach("sched", "sched_process_exit")?;
    info!("Tracepoint 'sched_process_exit' attached.");

    let fork_tp: &mut TracePoint = bpf.program_mut("handle_fork").unwrap().try_into()?;
    fork_tp.load()?;
    fork_tp.attach("sched", "sched_process_fork")?;
    info!("Tracepoint 'sched_process_fork' attached.");

    // 4. Attach LSM hooks
    let lsm_hooks = [
        ("handle_exec_lsm", "bprm_check_security"),
        ("handle_file_open", "file_open"),
        ("handle_file_create", "path_mknod"),
        ("handle_file_delete", "path_unlink"),
        ("handle_file_rename", "path_rename"),
        ("handle_net_connect", "socket_connect"),
        ("handle_net_bind", "socket_bind"),
        ("handle_net_accept", "socket_accept"),
    ];
    for (prog_name, hook) in &lsm_hooks {
        let program: &mut Lsm = bpf.program_mut(prog_name).unwrap().try_into()?;
        program.load(hook, &btf)?;
        program.attach()?;
        info!("LSM hook '{}' attached.", hook);
    }

    let cache: CgroupCache = Arc::new(build_cgroup_cache());
    let client = KubeClient::try_default().await?;
    let pods: Api<Pod> = Api::all(client.clone());
    sync_initial_pods(&pods, Arc::clone(&cache)).await?;

    let watcher_cache = Arc::clone(&cache);
    let watcher_pods = pods.clone();
    tokio::spawn(async move {
        let obs = watcher(watcher_pods, watcher::Config::default());
        pin_mut!(obs);
        while let Some(event_result) = obs.next().await {
            if let Ok(Event::Apply(pod)) | Ok(Event::InitApply(pod)) = event_result {
                refresh_cache_for_pod(Arc::clone(&watcher_cache), &pod);
            }
        }
    });

    let es_tx = es::spawn_shipper(EsConfig::default());
    info!(
        "ES shipper started → {}",
        std::env::var("ES_URL")
            .unwrap_or_else(|_| "http://skopos-es-es-http.skopos.svc:9200".into())
    );

    use aya::maps::RingBuf;
    use std::ptr;
    use tokio::io::unix::AsyncFd;

    let ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut async_ring = AsyncFd::new(ring_buf)?;
    let task_cache = Arc::clone(&cache);
    let client_handle = client.clone();

    tokio::spawn(async move {
        loop {
            let mut guard = match async_ring.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    error!("Ring buffer poll error: {}", e);
                    break;
                }
            };

            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let event: SensorEvent =
                    unsafe { ptr::read_unaligned(item.as_ptr() as *const SensorEvent) };

                let pod_identity = task_cache
                    .get(&event.cgroup_id)
                    .map(|v| v.value().clone())
                    .unwrap_or_else(|| format!("unknown:{}", event.cgroup_id));

                if event.event_type == EventType::ProcessExec {
                    let exec = unsafe { &event.data.exec };
                    let binary = str_from_bytes(&exec.filename);
                    let args_raw = parse_null_separated(&exec.args, 1024);
                    let is_shell =
                        binary.ends_with("/bash") || binary.ends_with("/sh");
                    let has_dash_c = args_raw.iter().any(|a| a == "-c");
                    if is_shell && has_dash_c && pod_identity.contains('/') {
                        warn!(
                            "CRITICAL: shell -c in pod {} | bin: {} | args: {:?}",
                            pod_identity, binary, args_raw
                        );
                        let c = client_handle.clone();
                        let id = pod_identity.clone();
                        tokio::spawn(async move {
                            if let Err(e) = kill_pod(c, &id).await {
                                error!("kill_pod failed for {}: {}", id, e);
                            }
                        });
                    }
                }

                dispatch_event(&event, &pod_identity, &es_tx);
            }

            guard.clear_ready();
        }
    });

    signal::ctrl_c().await?;
    info!("Skopos Sensor shutting down.");
    Ok(())
}
