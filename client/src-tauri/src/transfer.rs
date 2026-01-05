use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
// removed unused serde imports
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::Result;
use shared::{FileMessage, FileInfo};
use std::fs;

pub struct TransferServer {
    root_dir: PathBuf,
}

impl TransferServer {
    pub fn new(root_dir: PathBuf) -> Self {
        if !root_dir.exists() {
            let _ = fs::create_dir_all(&root_dir);
        }
        Self { root_dir }
    }

    pub async fn start(self: Arc<Self>, port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        log::info!("Transfer Server listening on port {}", port);

        loop {
            let (socket, addr) = listener.accept().await?;
            log::info!("Incoming transfer connection from {}", addr);
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(socket).await {
                    log::error!("Transfer error with {}: {}", addr, e);
                }
            });
        }
    }

    async fn handle_connection(&self, mut socket: TcpStream) -> Result<()> {
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await?;
        if n == 0 { return Ok(()); }

        let msg: FileMessage = serde_json::from_slice(&buf[..n])?;
        match msg {
            FileMessage::ListRequest { path } => {
                let res = self.list_files(path).await;
                let data = serde_json::to_vec(&res)?;
                socket.write_all(&data).await?;
            }
            FileMessage::DownloadRequest { path: _ } => {
                // TODO: Implement streaming file download
                let res = FileMessage::Error("Download not implemented yet".to_string());
                let data = serde_json::to_vec(&res)?;
                socket.write_all(&data).await?;
            }
            _ => {
                let res = FileMessage::Error("Invalid request".to_string());
                let data = serde_json::to_vec(&res)?;
                socket.write_all(&data).await?;
            }
        }
        Ok(())
    }

    async fn list_files(&self, sub_path: String) -> FileMessage {
        let full_path = self.root_dir.join(sub_path);
        // Security check: ensure path is within root_dir
        if !full_path.starts_with(&self.root_dir) {
            return FileMessage::Error("Access Denied".to_string());
        }

        match fs::read_dir(full_path) {
            Ok(entries) => {
                let mut files = Vec::new();
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        files.push(FileInfo {
                            name: entry.file_name().to_string_lossy().to_string(),
                            size: meta.len(),
                            path: entry.path().to_string_lossy().to_string(),
                            is_dir: meta.is_dir(),
                        });
                    }
                }
                FileMessage::ListResponse(files)
            }
            Err(e) => FileMessage::Error(e.to_string()),
        }
    }
}
