use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
    Json,
};
use dashmap::DashMap;
use futures::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use tokio::sync::mpsc;
use shared::{SignalingMessage, RegisterRequest, LoginRequest, AuthResponse};
use uuid::Uuid;
use chrono::prelude::*;
use bcrypt::{hash, DEFAULT_COST, verify};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String, // user_id
    exp: usize,
}

lazy_static::lazy_static! {
    static ref JWT_SECRET: String = std::env::var("JWT_SECRET").unwrap_or_else(|_| "change-me-for-production-security-12345678".to_string());
}

struct PeerState {
    tx: mpsc::Sender<Message>,
    udp_endpoint: Option<String>,
}

#[derive(Clone)]
struct AppState {
    peers: Arc<DashMap<String, PeerState>>,
    db: sqlx::SqlitePool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:server.db?mode=rwc".to_string());
    let db = sqlx::SqlitePool::connect(&db_url).await.unwrap();
    
    // 1. Create Users Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )"
    ).execute(&db).await.unwrap();

    // 2. Create Devices Table (Initial)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            hardware_id TEXT,
            name TEXT NOT NULL,
            public_key TEXT NOT NULL,
            virtual_ip TEXT,
            last_seen DATETIME,
            is_online BOOLEAN DEFAULT 0,
            UNIQUE(user_id, hardware_id)
        )"
    ).execute(&db).await.unwrap();

    // 3. Simple Migration: Ensure columns exist
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN user_id TEXT").execute(&db).await;
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN hardware_id TEXT").execute(&db).await;
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN virtual_ip TEXT").execute(&db).await;
    // Ensure the index exists for conflict resolution
    let _ = sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_hardware ON devices(user_id, hardware_id)").execute(&db).await;

    let state = AppState {
        peers: Arc::new(DashMap::new()),
        db,
    };

    // UDP Listener
    let state_udp = state.clone();
    tokio::spawn(async move {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:4000").await.unwrap();
        println!("UDP Signaling Listener at 0.0.0.0:4000");
        let mut buf = [0u8; 1024];
        loop {
            if let Ok((len, addr)) = sock.recv_from(&mut buf).await {
                if let Ok(msg) = serde_json::from_slice::<SignalingMessage>(&buf[..len]) {
                    if let SignalingMessage::Register { public_key } = msg {
                        if let Some(mut peer) = state_udp.peers.get_mut(&public_key) {
                            peer.udp_endpoint = Some(addr.to_string());
                        }
                    }
                }
            }
        }
    });

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/signup", post(signup_handler))
        .route("/api/login", post(login_handler))
        .route("/api/register_device", post(register_device_handler))
        .route("/api/devices", get(list_devices_handler))
        .route("/api/devices/:id", axum::routing::delete(delete_device_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Web Server running at 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn signup_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let hashed = match hash(payload.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Hash failed").into_response(),
    };

    let id = Uuid::new_v4().to_string();
    let res = sqlx::query("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(&payload.username)
        .bind(hashed)
        .execute(&state.db)
        .await;

    match res {
        Ok(_) => Json(AuthResponse {
            status: "success".into(),
            message: "User created".into(),
            token: None,
            assigned_ip: None,
        }).into_response(),
        Err(e) => {
            eprintln!("Signup failed: {}", e);
            (axum::http::StatusCode::BAD_REQUEST, "Username exists or DB error").into_response()
        }
    }
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: String,
    password_hash: String,
}

async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let user_res = sqlx::query_as::<_, UserRow>("SELECT id, password_hash FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(row)) = user_res {
        if verify(payload.password, &row.password_hash).unwrap_or(false) {
            let my_claims = Claims { sub: row.id, exp: 2000000000 };
            let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret(JWT_SECRET.as_bytes())).unwrap();
            
            return Json(AuthResponse {
                status: "success".into(),
                message: "Logged in".into(),
                token: Some(token),
                assigned_ip: None,
            }).into_response();
        }
    }
    
    (axum::http::StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
}

#[derive(Debug, Serialize, Deserialize)]
struct DeviceRegRequest {
    name: String,
    hardware_id: String,
    public_key: String,
}

async fn register_device_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<DeviceRegRequest>,
) -> impl IntoResponse {
    let user_id = match verify_token(&headers) {
        Some(id) => id,
        None => return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    println!("Registering device '{}' (HID: {}) for user '{}'", payload.name, payload.hardware_id, user_id);

    // 4. Assign a virtual IP if not already assigned
    let existing: Option<(Option<String>,)> = sqlx::query_as("SELECT virtual_ip FROM devices WHERE user_id = ? AND hardware_id = ?")
        .bind(&user_id)
        .bind(&payload.hardware_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let virtual_ip = if let Some((Some(ip),)) = existing {
        ip
    } else {
        // Simple allocation: Count existing devices for this user
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM devices WHERE user_id = ?")
            .bind(&user_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));
        format!("10.0.0.{}", count.0 + 2)
    };

    let dev_id = Uuid::new_v4().to_string();
    let res = sqlx::query(
        "INSERT INTO devices (id, user_id, hardware_id, name, public_key, virtual_ip) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, hardware_id) DO UPDATE SET 
            name = excluded.name, 
            public_key = excluded.public_key, 
            virtual_ip = CASE WHEN devices.virtual_ip IS NULL THEN excluded.virtual_ip ELSE devices.virtual_ip END,
            last_seen = DATETIME('now')"
    )
    .bind(&dev_id)
    .bind(&user_id)
    .bind(&payload.hardware_id)
    .bind(&payload.name)
    .bind(&payload.public_key)
    .bind(&virtual_ip)
    .execute(&state.db)
    .await;

    match res {
        Ok(_) => Json(serde_json::json!({"status": "success", "device_id": dev_id, "virtual_ip": virtual_ip})).into_response(),
        Err(e) => {
            eprintln!("Failed to register device: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("DB Error: {}", e)).into_response()
        }
    }
}

async fn list_devices_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let user_id = match verify_token(&headers) {
        Some(id) => id,
        None => return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let rows = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, name, public_key, virtual_ip, last_seen, is_online FROM devices WHERE user_id = ?"
    )
    .bind(&user_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let devices: Vec<shared::Device> = rows.into_iter().map(|r| {
        let is_online = state.peers.contains_key(&r.public_key);
        shared::Device {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            name: r.name,
            public_key: r.public_key,
            virtual_ip: r.virtual_ip,
            last_seen: r.last_seen,
            is_online,
        }
    }).collect();

    Json(devices).into_response()
}

async fn delete_device_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(device_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let user_id = match verify_token(&headers) {
        Some(id) => id,
        None => return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    println!("Deleting device {} for user {}", device_id, user_id);

    let _ = sqlx::query("DELETE FROM devices WHERE id = ? AND user_id = ?")
        .bind(device_id)
        .bind(user_id)
        .execute(&state.db)
        .await;

    Json(serde_json::json!({"status": "success"})).into_response()
}

fn verify_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let auth = headers.get("Authorization")?.to_str().ok()?;
    if !auth.starts_with("Bearer ") { return None; }
    let token = &auth[7..];
    let data = decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET.as_bytes()), &Validation::default()).ok()?;
    Some(data.claims.sub)
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: String,
    name: String,
    public_key: String,
    virtual_ip: Option<String>,
    last_seen: Option<DateTime<Utc>>,
    is_online: bool,
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    println!("New WebSocket connection attempt...");
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(32);
    
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() { break; }
        }
    });

    let mut my_pub_key: Option<String> = None;

    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(text) = msg {
            if let Ok(sig_msg) = serde_json::from_str::<SignalingMessage>(&text) {
                match sig_msg {
                    SignalingMessage::Register { public_key } => {
                        println!("WebSocket: Received Register for PK: {}", public_key);
                        my_pub_key = Some(public_key.clone());
                        state.peers.insert(public_key.clone(), PeerState {
                            tx: tx.clone(),
                            udp_endpoint: None,
                        });
                        let _ = sqlx::query("UPDATE devices SET last_seen = DATETIME('now'), is_online = 1 WHERE public_key = ?")
                            .bind(&public_key).execute(&state.db).await;
                    }
                    SignalingMessage::ConnectToPeer { peer_public_key } => {
                        println!("WebSocket: {} wants to connect to {}", my_pub_key.as_deref().unwrap_or("?"), peer_public_key);
                        if let Some(me_key) = &my_pub_key {
                             let target = state.peers.get(&peer_public_key).map(|p| (p.udp_endpoint.clone(), p.tx.clone()));
                             let me = state.peers.get(me_key).map(|p| (p.udp_endpoint.clone(), p.tx.clone()));
                             
                             if let (Some((t_ep, t_tx)), Some((m_ep, _))) = (target, me) {
                                 // Fetch virtual IPs from DB
                                 let t_vip: (Option<String>,) = sqlx::query_as("SELECT virtual_ip FROM devices WHERE public_key = ?").bind(&peer_public_key).fetch_one(&state.db).await.unwrap_or((None,));
                                 let m_vip: (Option<String>,) = sqlx::query_as("SELECT virtual_ip FROM devices WHERE public_key = ?").bind(me_key).fetch_one(&state.db).await.unwrap_or((None,));

                                 if let (Some(ep), Some(vip)) = (t_ep, t_vip.0) {
                                     let _ = tx.send(Message::Text(serde_json::to_string(&SignalingMessage::PeerInfo {
                                         peer_public_key: peer_public_key.clone(), 
                                         endpoint: ep,
                                         peer_virtual_ip: vip,
                                     }).unwrap())).await;
                                 }
                                 if let (Some(ep), Some(vip)) = (m_ep, m_vip.0) {
                                     let _ = t_tx.send(Message::Text(serde_json::to_string(&SignalingMessage::PeerInfo {
                                         peer_public_key: me_key.clone(), 
                                         endpoint: ep,
                                         peer_virtual_ip: vip,
                                     }).unwrap())).await;
                                 }
                             }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    
    send_task.abort();
    if let Some(pk) = my_pub_key {
        state.peers.remove(&pk);
        let _ = sqlx::query("UPDATE devices SET is_online = 0 WHERE public_key = ?").bind(&pk).execute(&state.db).await;
    }
}
