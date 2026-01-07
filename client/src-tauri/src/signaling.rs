use anyhow::Result;
use futures::{sink::SinkExt, stream::StreamExt};
use shared::SignalingMessage;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;
use std::sync::Arc;
use tokio::sync::Mutex;
use tauri::Emitter;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use std::time::Duration;

// Global sender for the signaling client
pub struct SignalingState {
    pub tx: Mutex<Option<mpsc::Sender<SignalingMessage>>>,
}

pub struct SignalingClient {}

impl SignalingClient {
    pub async fn start(
        server_url: String, 
        my_pub_key: String, 
        sig_state: Arc<SignalingState>,
        wg_controller: Arc<crate::wg_controller::WgController>,
        app_handle: tauri::AppHandle,
    ) -> Result<()> {
        // Fix URL scheme for WebSocket
        let mut ws_url = server_url.clone();
        if ws_url.starts_with("http://") {
            ws_url = ws_url.replacen("http://", "ws://", 1);
        } else if ws_url.starts_with("https://") {
            ws_url = ws_url.replacen("https://", "wss://", 1);
        }
        
        if !ws_url.ends_with("/ws") {
            if ws_url.ends_with("/") {
                ws_url.push_str("ws");
            } else {
                ws_url.push_str("/ws");
            }
        }

        println!("Connecting to signaling server: {}", ws_url);
        log::info!("Connecting to signaling server: {}", ws_url);
        
        let (ws_stream, _) = match connect_async(Url::parse(&ws_url)?).await {
            Ok(s) => s,
            Err(e) => {
                println!("❌ WebSocket Connection Failed: {}", e);
                log::error!("WebSocket Connection Failed: {}", e);
                return Err(e.into());
            }
        };
        println!("✅ Connected to signaling server!");
        let (mut write, mut read) = ws_stream.split();
        let (tx, mut rx) = mpsc::channel::<SignalingMessage>(32);

        // Store sender
        let mut guard = sig_state.tx.lock().await;
        *guard = Some(tx.clone()); // Keep clone for the global state
        
        // Send Register message immediately
        let register_msg = SignalingMessage::Register { public_key: my_pub_key.clone() };
        // Send via the WebSocket directly
        write.send(Message::Text(serde_json::to_string(&register_msg)?)).await?;
        // Also send via the mpsc channel for consistency if needed by other parts of the system
        let _ = tx.send(register_msg).await; 
        let _ = app_handle.emit("refresh-devices", ());


        // Writer task
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Ok(text) = serde_json::to_string(&msg) {
                    println!("DEBUG: Sending WS Message: {}", text);
                    if write.send(Message::Text(text)).await.is_err() {
                        log::error!("WS Write error");
                        break;
                    }
                }
            }
        });

        // Reader task
        tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                if let Message::Text(text) = msg {
                    if let Ok(sig_msg) = serde_json::from_str::<SignalingMessage>(&text) {
                        log::info!("Received Signaling Message: {:?}", sig_msg);
                        match sig_msg {
                            SignalingMessage::PeerInfo { peer_public_key, endpoint, peer_virtual_ip } => {
                                log::info!("PeerInfo received: {} @ {} (Internal: {})", peer_public_key, endpoint, peer_virtual_ip);
                                if let Err(e) = wg_controller.add_peer(peer_public_key, endpoint, peer_virtual_ip).await {
                                    log::error!("Failed to add peer: {}", e);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        });

        // Heartbeat task (UDP)
        let server_host = Url::parse(&server_url).ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "127.0.0.1".to_string());
            
        let my_pk_for_udp = my_pub_key.clone();
        tokio::spawn(async move {
            use tokio::net::lookup_host;
            
            // Resolve hostname to IP
            let server_addr = match lookup_host(format!("{}:4000", server_host)).await {
                Ok(mut addrs) => addrs.next().unwrap_or_else(|| "127.0.0.1:4000".parse().unwrap()),
                Err(e) => {
                    println!("❌ DNS Lookup failed for UDP: {}", e);
                    "127.0.0.1:4000".parse().unwrap()
                }
            };
            
            let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let msg = SignalingMessage::Register { public_key: my_pk_for_udp };
            let data = serde_json::to_vec(&msg).unwrap();
            
            println!("🚀 UDP Heartbeat task started. Server: {}", server_addr);
            loop {
                let _ = udp.send_to(&data, server_addr).await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        Ok(())
    }
    pub async fn connect_to_peer(peer_public_key: String, state: Arc<SignalingState>) -> Result<()> {
        let guard = state.tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            tx.send(SignalingMessage::ConnectToPeer { peer_public_key }).await
                .map_err(|_| anyhow::anyhow!("Signaling channel closed"))?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Signaling not connected"))
        }
    }
}
