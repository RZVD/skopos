use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, EbpfLoader};
use bytes::BytesMut;
use dashmap::DashMap;
use k8s_openapi::api::core::v1::Pod;
use log::{info, warn};
use regex::Regex;
use skopos_common::ExecEvent;
use std::ptr;
use std::sync::Arc;
use tokio::signal;
use walkdir::WalkDir;

use kube::runtime::watcher::{self, watcher, Event};
use kube::{
    api::{Api, DeleteParams},
    Client as KubeClient,
};
use std::fs;
use std::os::linux::fs::MetadataExt;

use futures::{pin_mut, StreamExt};

type CgroupCache = Arc<DashMap<u64, String>>;

async fn kill_pod(client: KubeClient, pod_identity: &str) -> anyhow::Result<()> {
    let parts: Vec<&str> = pod_identity.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid pod identity format: {}",
            pod_identity
        ));
    }
    let namespace = parts[0];
    let name = parts[1];

    info!(
        "HEURISTIC TRIGGERED: Killing pod {} in namespace {}",
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

fn parse_slots(data: &[u8], slot_size: usize) -> Vec<String> {
    data.chunks(slot_size)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .unwrap_or("")
                .trim_matches('\0')
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn extract_pod_uid(path: &str) -> Option<String> {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}").unwrap();
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
            if entry.path().to_string_lossy().contains(uid) {
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
    info!("Syncing pod names with API...");
    let pod_list = pods_api.list(&kube::api::ListParams::default()).await?;
    for pod in pod_list {
        refresh_cache_for_pod(Arc::clone(&cache), &pod);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    let mut ebpf = EbpfLoader::new()
        .btf(None)
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/skopos")))?;

    let program: &mut TracePoint = ebpf
        .program_mut("handle_execve")
        .expect("eBPF program not found")
        .try_into()?;

    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

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
            match event_result {
                Ok(Event::Apply(pod)) | Ok(Event::InitApply(pod)) => {
                    refresh_cache_for_pod(Arc::clone(&watcher_cache), &pod);
                }
                Ok(Event::Delete(pod)) => {
                    if let (Some(name), Some(ns)) =
                        (pod.metadata.name.as_ref(), pod.metadata.namespace.as_ref())
                    {
                        let identity = format!("{}/{}", ns, name);
                        watcher_cache.retain(|_, v| v != &identity);
                    }
                }
                Ok(Event::Init) | Ok(Event::InitDone) => {
                    info!("Watcher: Initial state sync complete.");
                }
                Err(e) => warn!("Watcher error: {}", e),
            }
        }
    });

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let cpus = online_cpus().map_err(|(_, e)| anyhow::anyhow!(e))?;

    info!("Skopos Watchman active. Monitoring executions...");

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let task_cache = Arc::clone(&cache);
        let client_handle = client.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<ExecEvent>()))
                .collect::<Vec<_>>();

            loop {
                if let Ok(events) = buf.read_events(&mut buffers).await {
                    for i in 0..events.read {
                        let event: ExecEvent =
                            unsafe { ptr::read(buffers[i].as_ptr() as *const ExecEvent) };

                        let pod_identity = task_cache
                            .get(&event.cgroup_id)
                            .map(|val| val.value().clone())
                            .unwrap_or_else(|| format!("unknown:{}", event.cgroup_id));

                        let filename = std::str::from_utf8(&event.filename)
                            .unwrap_or("?")
                            .trim_matches('\0');
                        let args_list = parse_slots(&event.args, 128);

                        // Simple heuristic check: kill pod on shell launch
                        let is_shell = filename.contains("bash") || filename.contains("sh");
                        let is_shell_c = args_list.get(1).map(|arg| arg == "-c").unwrap_or(false);

                        if is_shell && is_shell_c && pod_identity.contains('/') {
                            warn!("HEURISTIC TRIGGERED: Shell command in pod {}", pod_identity);

                            let internal_client = client_handle.clone();
                            let internal_id = pod_identity.clone();
                            tokio::spawn(async move {
                                if let Err(e) = kill_pod(internal_client, &internal_id).await {
                                    warn!("Failed to kill pod {}: {}", internal_id, e);
                                }
                            });
                        }

                        info!(
                            "[DETECTED] Pod: {} | Binary: {} | Args: {}",
                            pod_identity,
                            filename,
                            args_list.join(" ")
                        );
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;
    Ok(())
}
