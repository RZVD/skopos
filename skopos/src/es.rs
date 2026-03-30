use log::{error, info, warn};
use reqwest::Client;
use serde::Serialize;
use serde_json;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

pub struct EsConfig {
    pub url: String,
    pub index: String,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
}

impl Default for EsConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("ES_URL")
                .unwrap_or_else(|_| "http://skopos-es-es-http.skopos.svc:9200".into()),
            index: std::env::var("ES_INDEX").unwrap_or_else(|_| "skopos-events".into()),
            batch_size: 100,
            flush_interval_ms: 2000,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum SkoposEvent {
    ProcessExec {
        pod: String,
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: String,
        binary: String,
        args: Vec<String>,
        envs: Vec<String>,
    },
    ProcessExit {
        pod: String,
        pid: u32,
        uid: u32,
        comm: String,
        exit_code: i32,
    },
    ProcessFork {
        pod: String,
        ppid: u32,
        parent_comm: String,
        child_pid: u32,
        child_comm: String,
    },
    FileOpen {
        pod: String,
        pid: u32,
        uid: u32,
        comm: String,
        path: String,
    },
    FileCreate {
        pod: String,
        pid: u32,
        uid: u32,
        comm: String,
        path: String,
    },
    FileDelete {
        pod: String,
        pid: u32,
        uid: u32,
        comm: String,
        path: String,
    },
    FileRename {
        pod: String,
        pid: u32,
        uid: u32,
        comm: String,
        from: String,
    },
    NetConnect {
        pod: String,
        pid: u32,
        uid: u32,
        comm: String,
        dst: String,
        proto: String,
    },
    NetBind {
        pod: String,
        pid: u32,
        uid: u32,
        comm: String,
        addr: String,
        proto: String,
    },
    NetAccept {
        pod: String,
        pid: u32,
        uid: u32,
        comm: String,
    },
}

pub fn spawn_shipper(config: EsConfig) -> mpsc::Sender<SkoposEvent> {
    let (tx, mut rx) = mpsc::channel::<SkoposEvent>(8192);

    tokio::spawn(async move {
        let client = Client::new();
        let mut batch: Vec<SkoposEvent> = Vec::with_capacity(config.batch_size);
        let mut ticker = interval(Duration::from_millis(config.flush_interval_ms));

        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(e) => {
                            batch.push(e);
                            if batch.len() >= config.batch_size {
                                flush(&client, &config, &mut batch).await;
                            }
                        }
                        None => {
                            if !batch.is_empty() {
                                flush(&client, &config, &mut batch).await;
                            }
                            info!("ES shipper: channel closed, exiting.");
                            return;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !batch.is_empty() {
                        flush(&client, &config, &mut batch).await;
                    }
                }
            }
        }
    });

    tx
}

async fn flush(client: &Client, config: &EsConfig, batch: &mut Vec<SkoposEvent>) {
    let body = build_bulk_body(&config.index, batch);
    batch.clear();

    let url = format!("{}/_bulk", config.url);
    match client
        .post(&url)
        .header("Content-Type", "application/x-ndjson")
        .body(body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
        }
        Ok(resp) => {
            warn!("ES bulk returned {}", resp.status());
        }
        Err(e) => {
            error!("ES bulk request failed: {:?}", e);
        }
    }
}

fn build_bulk_body(index: &str, events: &[SkoposEvent]) -> String {
    let action = format!("{{\"index\":{{\"_index\":\"{}\"}}}}", index);
    let mut body = String::new();
    for event in events {
        body.push_str(&action);
        body.push('\n');
        match serde_json::to_string(event) {
            Ok(doc) => body.push_str(&doc),
            Err(e) => {
                error!("Failed to serialize event: {}", e);
                body.push_str("{}");
            }
        }
        body.push('\n');
    }
    body
}
