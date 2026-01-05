use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
pub use shared::{RegisterRequest, LoginRequest, AuthResponse};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    pub async fn listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> JsValue;
}

pub async fn signup(server_url: String, req: RegisterRequest) -> Result<AuthResponse, String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "serverUrl")]
        server_url: String,
        req: RegisterRequest,
    }
    let args = serde_wasm_bindgen::to_value(&Args { server_url, req }).unwrap();
    let res = invoke("signup", args).await;
    serde_wasm_bindgen::from_value(res).map_err(|e| format!("{:?}", e))
}

pub async fn login(server_url: String, req: LoginRequest) -> Result<AuthResponse, String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "serverUrl")]
        server_url: String,
        req: LoginRequest,
    }
    let args = serde_wasm_bindgen::to_value(&Args { server_url, req }).unwrap();
    let res = invoke("login", args).await;
    serde_wasm_bindgen::from_value(res).map_err(|e| format!("{:?}", e))
}

pub async fn register_device(server_url: String, token: String, name: String, hardware_id: String, public_key: String) -> Result<String, String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "serverUrl")]
        server_url: String,
        token: String,
        name: String,
        #[serde(rename = "hardwareId")]
        hardware_id: String,
        #[serde(rename = "publicKey")]
        public_key: String,
    }
    let args = serde_wasm_bindgen::to_value(&Args { server_url, token, name, hardware_id, public_key }).unwrap();
    let res = invoke("register_device", args).await;
    Ok(serde_wasm_bindgen::from_value(res).unwrap_or_default())
}

pub async fn list_devices(server_url: String, token: String) -> Result<Vec<shared::Device>, String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "serverUrl")]
        server_url: String,
        token: String,
    }
    let args = serde_wasm_bindgen::to_value(&Args { server_url, token }).unwrap();
    let res = invoke("list_devices", args).await;
    serde_wasm_bindgen::from_value(res).map_err(|e| format!("{:?}", e))
}

pub async fn connect_device(peer_public_key: String) -> Result<(), String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "peerPublicKey")]
        peer_public_key: String,
    }
    let args = serde_wasm_bindgen::to_value(&Args { peer_public_key }).unwrap();
    invoke("connect_device", args).await;
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WgKeys {
    pub private_key: String,
    pub public_key: String,
}

pub async fn generate_wg_keys() -> Result<WgKeys, String> {
    let res = invoke("generate_wg_keys", JsValue::NULL).await;
    serde_wasm_bindgen::from_value(res).map_err(|e| format!("{:?}", e))
}

pub async fn start_signaling(server_url: String, my_pub_key: String) -> Result<(), String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "myPubKey")]
        my_pub_key: String,
    }
    let args = serde_wasm_bindgen::to_value(&Args { server_url, my_pub_key }).unwrap();
    invoke("start_signaling", args).await;
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AppConfig {
    #[serde(rename = "server_url")]
    pub server_url: Option<String>,
    pub username: Option<String>,
    pub token: Option<String>,
    #[serde(rename = "private_key")]
    pub private_key: Option<String>,
    #[serde(rename = "public_key")]
    pub public_key: Option<String>,
    #[serde(rename = "hardware_id")]
    pub hardware_id: Option<String>,
    #[serde(rename = "virtual_ip")]
    pub virtual_ip: Option<String>,
}

pub async fn get_config() -> Result<AppConfig, String> {
    let res = invoke("get_config", JsValue::NULL).await;
    serde_wasm_bindgen::from_value(res).map_err(|e| format!("{:?}", e))
}

pub async fn save_config(config: AppConfig) -> Result<(), String> {
    #[derive(Serialize)]
    struct Args { config: AppConfig }
    let args = serde_wasm_bindgen::to_value(&Args { config }).unwrap();
    invoke("save_config", args).await;
    Ok(())
}

pub async fn start_wg_interface(private_key: String, virtual_ip: String) -> Result<(), String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "privateKey")]
        private_key: String,
        #[serde(rename = "virtualIp")]
        virtual_ip: String,
    }
    let args = serde_wasm_bindgen::to_value(&Args { private_key, virtual_ip }).unwrap();
    invoke("start_wg_interface", args).await;
    Ok(())
}

pub async fn list_remote_files(peer_ip: String, path: String) -> Result<Vec<shared::FileInfo>, String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "peerIp")]
        peer_ip: String,
        path: String,
    }
    let args = serde_wasm_bindgen::to_value(&Args { peer_ip, path }).unwrap();
    let res = invoke("list_remote_files", args).await;
    serde_wasm_bindgen::from_value(res).map_err(|e| format!("{:?}", e))
}

pub async fn get_hostname() -> Result<String, String> {
    let res = invoke("get_hostname", JsValue::NULL).await;
    serde_wasm_bindgen::from_value(res).map_err(|e| format!("{:?}", e))
}

pub async fn delete_device(server_url: String, token: String, device_id: String) -> Result<(), String> {
    #[derive(Serialize)]
    struct Args {
        #[serde(rename = "serverUrl")]
        server_url: String,
        token: String,
        #[serde(rename = "deviceId")]
        device_id: String,
    }
    let args = serde_wasm_bindgen::to_value(&Args { server_url, token, device_id }).unwrap();
    invoke("delete_device", args).await;
    Ok(())
}
