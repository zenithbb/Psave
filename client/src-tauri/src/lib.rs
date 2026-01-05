pub mod wg_controller;
pub mod signaling;

use std::sync::Arc;
use tokio::sync::Mutex;
use tauri::State;
use tauri::Manager;
use wg_controller::WgController;
use signaling::SignalingState;
use shared::{RegisterRequest, LoginRequest, AuthResponse};

mod api;
mod config;
mod transfer;

#[tauri::command]
fn get_hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

#[tauri::command]
async fn signup(server_url: String, req: RegisterRequest) -> Result<AuthResponse, String> {
    api::signup_http(server_url, req).await
}

#[tauri::command]
async fn login(server_url: String, req: LoginRequest) -> Result<AuthResponse, String> {
    api::login_http(server_url, req).await
}

#[tauri::command]
async fn register_device(server_url: String, token: String, name: String, hardware_id: String, public_key: String) -> Result<String, String> {
    api::register_device_http(server_url, token, name, hardware_id, public_key).await
}

#[tauri::command]
async fn delete_device(server_url: String, token: String, device_id: String) -> Result<(), String> {
    api::delete_device_http(server_url, token, device_id).await
}

#[tauri::command]
async fn list_devices(server_url: String, token: String) -> Result<Vec<shared::Device>, String> {
    api::list_devices_http(server_url, token).await
}

#[tauri::command]
async fn connect_device(
    peer_public_key: String, 
    state: State<'_, Arc<SignalingState>>
) -> Result<(), String> {
    signaling::SignalingClient::connect_to_peer(peer_public_key, state.inner().clone())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn start_signaling(
    server_url: String, 
    my_pub_key: String, 
    sig_state: State<'_, Arc<SignalingState>>,
    wg_state: State<'_, Arc<WgController>>,
    app_handle: tauri::AppHandle
) -> Result<(), String> {
    signaling::SignalingClient::start(
        server_url, 
        my_pub_key, 
        sig_state.inner().clone(),
        wg_state.inner().clone(),
        app_handle
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn start_wg_interface(
    private_key: String, 
    virtual_ip: String,
    wg_state: State<'_, Arc<WgController>>
) -> Result<(), String> {
    let controller = wg_state.inner().clone();
    controller.start_interface(private_key, virtual_ip, 51820).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_remote_files(peer_ip: String, path: String) -> Result<Vec<shared::FileInfo>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(format!("{}:9000", peer_ip)).await.map_err(|e| e.to_string())?;
    let req = shared::FileMessage::ListRequest { path };
    let data = serde_json::to_vec(&req).unwrap();
    stream.write_all(&data).await.map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    let res: shared::FileMessage = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;
    
    match res {
        shared::FileMessage::ListResponse(files) => Ok(files),
        shared::FileMessage::Error(e) => Err(e),
        _ => Err("Unexpected response".to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let config_state = Arc::new(config::ConfigState::new(app.handle()));
            let app_data_dir = app.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("./data"));
            let share_dir = app_data_dir.join("Shared");
            
            let transfer_server = Arc::new(transfer::TransferServer::new(share_dir));
            app.manage(transfer_server.clone());

            tauri::async_runtime::spawn(async move {
                let _ = transfer_server.start(9000).await;
            });

            app.manage(config_state);
            Ok(())
        })
        .manage(Arc::new(SignalingState { tx: Mutex::new(None) }))
        .manage(Arc::new(WgController::new()))
        .invoke_handler(tauri::generate_handler![
            wg_controller::generate_wg_keys,
            start_signaling,
            signup,
            login,
            register_device,
            list_devices,
            delete_device,
            connect_device,
            start_wg_interface,
            list_remote_files,
            get_hostname,
            config::commands::get_config,
            config::commands::save_config
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
