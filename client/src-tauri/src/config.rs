use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::AppHandle;
use tauri::Manager;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AppConfig {
    pub server_url: Option<String>,
    pub username: Option<String>,
    pub token: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub hardware_id: Option<String>,
    pub virtual_ip: Option<String>,
}

pub struct ConfigState {
    pub config: Mutex<AppConfig>,
    pub path: PathBuf,
}

impl ConfigState {
    pub fn new(app_handle: &AppHandle) -> Self {
        let path = app_handle.path().app_data_dir().unwrap().join("config.json");
        let config = if path.exists() {
            let content = fs::read_to_string(&path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            AppConfig::default()
        };
        
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        Self {
            config: Mutex::new(config),
            path,
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let config = self.config.lock().map_err(|e| e.to_string())?;
        let content = serde_json::to_string_pretty(&*config).map_err(|e| e.to_string())?;
        fs::write(&self.path, content).map_err(|e| e.to_string())
    }
}

pub mod commands {
    use super::*;
    use tauri::State;
    use std::sync::Arc;

    #[tauri::command]
    pub fn get_config(state: State<'_, Arc<ConfigState>>) -> Result<AppConfig, String> {
        let config = state.config.lock().map_err(|e| e.to_string())?;
        Ok(config.clone())
    }

    #[tauri::command]
    pub fn save_config(
        config: AppConfig,
        state: State<'_, Arc<ConfigState>>
    ) -> Result<(), String> {
        {
            let mut guard = state.config.lock().map_err(|e| e.to_string())?;
            *guard = config;
        }
        state.save()
    }
}
