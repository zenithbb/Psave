use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "payload")]
pub enum SignalingMessage {
    /// Client identifies itself with its WG Public Key
    ConnectSuccess,
    Register { public_key: String },
    /// Client wants to connect to a specific Peer (by PubKey)
    ConnectToPeer { peer_public_key: String },
    /// Server notifies Client of a Peer's endpoint (for hole punching)
    PeerInfo { 
        peer_public_key: String, 
        endpoint: String, // "IP:PORT"
        peer_virtual_ip: String,
    },
    /// KeepAlive to keep the NAT mapping open
    KeepAlive,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub public_key: String, 
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthResponse {
    pub status: String,
    pub message: String,
    pub token: Option<String>,
    pub assigned_ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Device {
    pub id: uuid::Uuid,
    pub name: String,
    pub public_key: String,
    pub virtual_ip: Option<String>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub is_online: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub path: String,
    pub is_dir: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FileMessage {
    ListRequest { path: String },
    ListResponse(Vec<FileInfo>),
    DownloadRequest { path: String },
    DownloadResponse { 
        name: String,
        size: u64,
        // Data usually streamed separately for large files
    },
    Error(String),
}
