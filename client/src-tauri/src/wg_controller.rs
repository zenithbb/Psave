use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::rngs::OsRng;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tun::Device;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WgKeys {
    pub private_key: String,
    pub public_key: String,
}

pub enum WgCommand {
    AddPeer { public_key: String, endpoint: String, allowed_ips: String },
    RemovePeer { public_key: String },
}

// removed unused log imports
use std::collections::HashMap;
use std::net::SocketAddr;

pub struct PeerState {
    pub tunnel: Box<boringtun::noise::Tunn>,
    pub endpoint: SocketAddr,
    pub internal_ip: String,
}

pub struct WgController {
    cmd_tx: Mutex<Option<mpsc::Sender<WgCommand>>>,
    udp_socket: Mutex<Option<Arc<tokio::net::UdpSocket>>>,
}

impl WgController {
    pub fn new() -> Self {
        Self {
            cmd_tx: Mutex::new(None),
            udp_socket: Mutex::new(None),
        }
    }

    pub async fn get_socket(&self) -> Option<Arc<tokio::net::UdpSocket>> {
        self.udp_socket.lock().await.clone()
    }

    pub fn generate_keys() -> WgKeys {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        WgKeys {
            private_key: BASE64.encode(private_key.to_bytes()),
            public_key: BASE64.encode(public_key.as_bytes()),
        }
    }

    pub async fn start_interface(
        &self,
        private_key: String,
        virtual_ip: String,
        local_port: u16,
    ) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(32);
        *self.cmd_tx.lock().await = Some(tx);

        let private_key_bytes = BASE64.decode(&private_key)?;
        if private_key_bytes.len() != 32 {
             return Err(anyhow::anyhow!("Invalid private key length"));
        }
        let private_key_arr: [u8; 32] = private_key_bytes.try_into().unwrap();
        let _my_public_key = PublicKey::from(&StaticSecret::from(private_key_arr));

        // 1. Create TUN device
        let ip_parts: Vec<u8> = virtual_ip.split('.')
            .map(|s| s.parse().unwrap_or(0))
            .collect();
        if ip_parts.len() != 4 {
             return Err(anyhow::anyhow!("Invalid Virtual IP format: {}", virtual_ip));
        }

        // 1. Bind UDP Socket first
        let udp_socket = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?;
        println!("UDP Socket bound to {}", udp_socket.local_addr()?);
        let udp_socket = Arc::new(udp_socket);
        *self.udp_socket.lock().await = Some(udp_socket.clone());

        // 2. Create TUN device (keep non-Send config in a narrow scope)
        let tun_device = {
            let mut config = tun::Configuration::default();
            config
                .address((ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]))
                .netmask((255, 255, 255, 0))
                .up();
            
            #[cfg(target_os = "linux")]
            config.platform(|config| { config.packet_information(true); });

            tun::create_as_async(&config).map_err(|e| anyhow::anyhow!("Failed to create TUN: {}", e))?
        };

        let tun_name = tun_device.get_ref().name().unwrap_or_default();
        println!("Created TUN device: {}", tun_name);

        #[cfg(target_os = "macos")]
        {
            // On macOS, we need to manually add the subnet route to the routing table
            let status = std::process::Command::new("route")
                .args(&["add", "-net", "10.0.0.0/24", "-interface", &tun_name])
                .status();
            match status {
                Ok(s) if s.success() => println!("✅ Added subnet route for {}", tun_name),
                _ => println!("⚠️ Failed to add subnet route or it already exists (requires sudo)"),
            }
        }

        // 3. Routing and Peer State
        let mut peers: HashMap<String, Arc<Mutex<PeerState>>> = HashMap::new();
        let mut ip_to_pubkey: HashMap<String, String> = HashMap::new();

        // 4. Packet Loop
        tokio::spawn(async move {
            let mut buf_tun = [0u8; 2048];
            let mut buf_udp = [0u8; 2048];
            let mut buf_out = [0u8; 4096]; // Slightly larger for overhead

            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut tun_reader, mut tun_writer) = tokio::io::split(tun_device);

            loop {
                tokio::select! {
                    // Command handling (Add/Remove Peers)
                    cmd = rx.recv() => {
                        match cmd {
                            Some(WgCommand::AddPeer { public_key, endpoint, allowed_ips }) => {
                                println!("Adding Peer: {} @ {}", public_key, endpoint);
                                if let (Ok(peer_key_bytes), Ok(addr)) = (BASE64.decode(&public_key), endpoint.parse::<SocketAddr>()) {
                                    if let Ok(peer_static_bytes) = <[u8; 32]>::try_from(peer_key_bytes.as_slice()) {
                                        let my_secret = StaticSecret::from(private_key_arr);
                                        let peer_public = PublicKey::from(peer_static_bytes);
                                        
                                        // CORRECT: Tunn::new(static_private, peer_static_public, ...)
                                        match boringtun::noise::Tunn::new(my_secret, peer_public, None, None, 0, None) {
                                            Ok(tunnel) => {
                                                let peer_state = Arc::new(Mutex::new(PeerState {
                                                    tunnel: Box::new(tunnel),
                                                    endpoint: addr,
                                                    internal_ip: allowed_ips.clone(),
                                                }));

                                                peers.insert(public_key.clone(), peer_state.clone());
                                                ip_to_pubkey.insert(allowed_ips.clone(), public_key.clone());

                                                // --- Background Timer Task ---
                                                let peer_timer = peer_state.clone();
                                                let udp_timer = udp_socket.clone();
                                                tokio::spawn(async move {
                                                    let mut timer_buf = [0u8; 2048];
                                                    loop {
                                                        let mut p = peer_timer.lock().await;
                                                        match p.tunnel.update_timers(&mut timer_buf) {
                                                            boringtun::noise::TunnResult::WriteToNetwork(packet) => {
                                                                let current_addr = p.endpoint;
                                                                let _ = udp_timer.send_to(packet, current_addr).await;
                                                            }
                                                            _ => {}
                                                        }
                                                        drop(p);
                                                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                                    }
                                                });

                                                // --- Initial Handshake ---
                                                let mut p = peer_state.lock().await;
                                                let mut hs_buf = [0u8; 2048];
                                                match p.tunnel.encapsulate(&[], &mut hs_buf) {
                                                    boringtun::noise::TunnResult::WriteToNetwork(packet) => {
                                                        let _ = udp_socket.send_to(packet, addr).await;
                                                        println!("DEBUG: Sent proactive handshake to {}", addr);
                                                    }
                                                    _ => {}
                                                }
                                            },
                                            Err(e) => println!("❌ Failed to create tunnel for peer: {}", e),
                                        }
                                    }
                                }
                            }
                            Some(WgCommand::RemovePeer { public_key }) => {
                                peers.remove(&public_key);
                            }
                            None => break,
                        }
                    }

                    // Read from TUN -> Encapsulate -> UDP
                    res = tun_reader.read(&mut buf_tun) => {
                        if let Ok(n) = res {
                            let packet = &buf_tun[..n];
                            if n >= 4 {
                                println!("DEBUG: [TUN READ] {} bytes, Lead: {:02x} {:02x} {:02x} {:02x}", n, packet[0], packet[1], packet[2], packet[3]);
                            }
                            if n < 20 { continue; } 
                            
                            // macOS utun adds a 4-byte header (00 00 00 02 for IPv4)
                            let offset = if packet[0] == 0 && packet[1] == 0 && n >= 24 { 4 } else { 0 };
                            
                            // Simple IPv4 Destination IP Extraction
                            let dest_ip = format!("{}.{}.{}.{}", packet[offset + 16], packet[offset + 17], packet[offset + 18], packet[offset + 19]);
                            
                            if let Some(pubkey) = ip_to_pubkey.get(&dest_ip) {
                                if let Some(peer_state_lock) = peers.get(pubkey) {
                                    let mut peer = peer_state_lock.lock().await;
                                    println!("DEBUG: [TUN -> UDP] Routing packet to {}. Size: {}", dest_ip, n);
                                    match peer.tunnel.encapsulate(&packet[offset..], &mut buf_out) {
                                        boringtun::noise::TunnResult::WriteToNetwork(enc_packet) => {
                                            let _ = udp_socket.send_to(enc_packet, peer.endpoint).await;
                                        },
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }

                    // Read from UDP -> Decapsulate -> TUN
                    res = udp_socket.recv_from(&mut buf_udp) => {
                         if let Ok((size, src_addr)) = res {
                             let packet = &buf_udp[..size];
                             
                             // Find peer by endpoint or try all (simpler to try all decaps for now if endpoint mapping isn't perfect)
                             for peer_state_lock in peers.values() {
                                 let mut peer = peer_state_lock.lock().await;
                                 match peer.tunnel.decapsulate(Some(src_addr.ip()), packet, &mut buf_out) {
                                     boringtun::noise::TunnResult::WriteToTunnelV4(packet, _) | 
                                     boringtun::noise::TunnResult::WriteToTunnelV6(packet, _) => {
                                         println!("DEBUG: [UDP -> TUN] Writing packet to local TUN. Size: {}", packet.len());
                                         
                                         #[cfg(target_os = "macos")]
                                         {
                                             let mut pi_packet = vec![0u8, 0, 0, 2];
                                             pi_packet.extend_from_slice(packet);
                                             let _ = tun_writer.write_all(&pi_packet).await;
                                         }
                                         #[cfg(not(target_os = "macos"))]
                                         {
                                             let _ = tun_writer.write_all(packet).await;
                                         }
                                         
                                         // Update endpoint in case it changed (mobility)
                                         peer.endpoint = src_addr;
                                         break;
                                     },
                                     boringtun::noise::TunnResult::WriteToNetwork(packet) => {
                                         println!("DEBUG: [UDP -> UDP] Sending handshake/response back to peer.");
                                         let _ = udp_socket.send_to(packet, src_addr).await;
                                         break;
                                     }, 
                                     _ => {}
                                 }
                             }
                         }
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn add_peer(&self, public_key: String, endpoint: String, internal_ip: String) -> Result<()> {
        if let Some(tx) = self.cmd_tx.lock().await.as_ref() {
            tx.send(WgCommand::AddPeer { 
                public_key, 
                endpoint, 
                allowed_ips: internal_ip 
            }).await.map_err(|_| anyhow::anyhow!("Interface not running"))?;
        }
        Ok(())
    }
}

#[tauri::command]
pub fn generate_wg_keys() -> WgKeys {
    WgController::generate_keys()
}
