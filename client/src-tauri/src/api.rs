// removed unused serde imports
use shared::{RegisterRequest, LoginRequest, AuthResponse};

pub async fn signup_http(server_url: String, req: RegisterRequest) -> Result<AuthResponse, String> {
    let url = format!("{}/api/signup", server_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let res = client.post(url).json(&req).send().await.map_err(|e| e.to_string())?;
    res.json::<AuthResponse>().await.map_err(|e| e.to_string())
}

pub async fn login_http(server_url: String, req: LoginRequest) -> Result<AuthResponse, String> {
    let url = format!("{}/api/login", server_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let res = client.post(url).json(&req).send().await.map_err(|e| e.to_string())?;
    res.json::<AuthResponse>().await.map_err(|e| e.to_string())
}

pub async fn register_device_http(server_url: String, token: String, name: String, hardware_id: String, public_key: String) -> Result<String, String> {
    let url = format!("{}/api/register_device", server_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    println!("Sending POST request to {}", url);
    let res = client.post(url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({ "name": name, "hardware_id": hardware_id, "public_key": public_key }))
        .send().await.map_err(|e| format!("Send Error: {}", e))?;
    
    println!("Received Response Status: {}", res.status());

    if res.status().is_success() {
        let text = res.text().await.map_err(|e| format!("Read Body Error: {}", e))?;
        println!("Received Body: {}", text);
        
        let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("Parse JSON Error: {}", e))?;
        Ok(json["virtual_ip"].as_str().unwrap_or_default().to_string())
    } else {
        Err(format!("Error: {}", res.status()))
    }
}

pub async fn list_devices_http(server_url: String, token: String) -> Result<Vec<shared::Device>, String> {
    let url = format!("{}/api/devices", server_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let res = client.get(url)
        .header("Authorization", format!("Bearer {}", token))
        .send().await.map_err(|e| e.to_string())?;
        
    if res.status().is_success() {
        res.json::<Vec<shared::Device>>().await.map_err(|e| e.to_string())
    } else {
        Err(format!("Error: {}", res.status()))
    }
}

pub async fn delete_device_http(server_url: String, token: String, device_id: String) -> Result<(), String> {
    let url = format!("{}/api/devices/{}", server_url.trim_end_matches('/'), device_id);
    let client = reqwest::Client::new();
    let res = client.delete(url)
        .header("Authorization", format!("Bearer {}", token))
        .send().await.map_err(|e| e.to_string())?;
        
    if res.status().is_success() { Ok(()) } else { Err(format!("Error: {}", res.status())) }
}
