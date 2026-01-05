use leptos::prelude::*;
use leptos_router::{components::*, hooks::use_navigate, path};
use leptos::task::spawn_local;

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <div class="app-container">
                <Routes fallback=|| "Not Found">
                    <Route path=path!("/") view=Home/>
                    <Route path=path!("/auth") view=AuthPage/>
                    <Route path=path!("/files/:ip") view=FileBrowser/>
                </Routes>
            </div>
        </Router>
    }
}

#[component]
fn Home() -> impl IntoView {
    let navigate = use_navigate();
    let (config, set_config) = signal(crate::invoke::AppConfig::default());
    
    let load_config = LocalResource::new(|| async move {
        crate::invoke::get_config().await
    });

    Effect::new(move |_| {
        let navigate = navigate.clone();
        if let Some(data) = load_config.get() {
            if let Ok(c) = (*data).clone() {
                set_config.set(c.clone());
                if c.token.is_none() {
                    navigate("/auth", Default::default());
                } else if let (Some(server), Some(pk), Some(sk)) = (c.server_url.clone(), c.public_key.clone(), c.private_key.clone()) {
                    let vip = c.virtual_ip.clone().unwrap_or_else(|| "10.0.0.2".to_string());
                    spawn_local(async move {
                        let _ = crate::invoke::start_wg_interface(sk, vip).await;
                        let _ = crate::invoke::start_signaling(server, pk).await;
                    });
                }
            }
        }
    });

    let devices = LocalResource::new(move || {
        let c = config.get();
        async move {
            if let (Some(url), Some(token)) = (c.server_url, c.token) {
                crate::invoke::list_devices(url, token).await
            } else {
                Err("Not logged in".to_string())
            }
        }
    });

    // Handle auto-refresh in its own effect
    Effect::new(move |_| {
        let devices_ref = devices.clone();
        spawn_local(async move {
            use wasm_bindgen::prelude::Closure;
            let callback = Closure::wrap(Box::new(move |_| {
                println!("Frontend: Received refresh-devices event");
                devices_ref.refetch();
            }) as Box<dyn FnMut(wasm_bindgen::JsValue)>);
            
            crate::invoke::listen("refresh-devices", &callback).await;
            callback.forget();
        });
    });

    view! {
        <div class="card">
            <div style="display:flex; justify-content:space-between; align-items:center">
                <h1>"My Network"</h1>
                <button class="btn-sm" style="background:#ef4444" on:click=move |_| {
                    spawn_local(async {
                        let mut c = crate::invoke::get_config().await.unwrap_or_default();
                        c.token = None;
                        let _ = crate::invoke::save_config(c).await;
                        window().location().reload().unwrap();
                    });
                }>"Logout"</button>
            </div>
            
            <Suspense fallback=|| view! { <p class="status">"Syncing..."</p> }>
                {move || match devices.get() {
                    None => view! { <p class="status">"Loading..."</p> }.into_any(),
                    Some(data) => match (*data).clone() {
                        Ok(items) => {
                            let items_view = items.into_iter().map(|d| {
                                view! {
                                    <div class="device-item">
                                        <div style="display:flex; flex-direction:column; flex: 1">
                                            <div style="display:flex; align-items:center">
                                                <span class=format!("online-dot {}", if d.is_online { "online" } else { "offline" })></span>
                                                <strong style="font-size: 15px">{d.name.clone()}</strong>
                                            </div>
                                            <span style="font-size:10px; color:#9ca3af; margin-left: 16px; font-family: monospace">"ID: " {d.id.to_string()[..8].to_string()}</span>
                                        </div>
                                        <div style="display:flex; align-items:center; gap: 8px">
                                            {if d.is_online {
                                                view! {
                                                    <button class="btn-sm btn-primary" on:click=move |_| {
                                                        let key = d.public_key.clone();
                                                        spawn_local(async move {
                                                             let _ = crate::invoke::connect_device(key).await;
                                                        });
                                                    }>"Connect"</button>
                                                    <a href=format!("/files/10.0.0.1") class="btn-sm btn-outline" style="text-decoration:none">"Browse"</a>
                                                }.into_any()
                                            } else {
                                                view! { <span class="status" style="margin:0; font-size:12px">"Offline"</span> }.into_any()
                                            }}
                                            <button class="btn-sm btn-danger" on:click=move |_| {
                                                let id = d.id.clone();
                                                let c = config.get();
                                                spawn_local(async move {
                                                    if let (Some(url), Some(token)) = (c.server_url, c.token) {
                                                        let _ = crate::invoke::delete_device(url, token, id.to_string()).await;
                                                        devices.refetch();
                                                    }
                                                });
                                            }>"Remove"</button>
                                        </div>
                                    </div>
                                }
                            }).collect_view();

                            view! {
                                <div style="margin-top: 20px;">
                                    {items_view}
                                </div>
                            }.into_any()
                        },
                        Err(e) => view! { <p class="status" style="color:#ef4444">"Error: " {e}</p> }.into_any(),
                    }
                }}
            </Suspense>
            <button on:click=move |_| { devices.refetch(); }>"Refresh List"</button>
        </div>
    }
}

#[component]
fn AuthPage() -> impl IntoView {
    let navigate = use_navigate();
    let (is_signup, set_is_signup) = signal(false);
    let (username, set_username) = signal("".to_string());
    let (password, set_password) = signal("".to_string());
    let (server_url, set_server_url) = signal("https://niwelt.duckdns.org".to_string());
    let (status, set_status) = signal("".to_string());

    let on_submit = move |_| {
        let user = username.get();
        let pass = password.get();
        let mut server = server_url.get().trim().to_string();
        if !server.starts_with("http") { server = format!("http://{}", server); }

        set_status.set("Authenticating...".into());
        
        let navigate = navigate.clone();
        spawn_local(async move {
            if is_signup.get() {
                // Register User
                let keys = crate::invoke::generate_wg_keys().await.unwrap();
                let req = crate::invoke::RegisterRequest {
                    username: user.clone(),
                    password: pass.clone(),
                    public_key: keys.public_key.clone(),
                };
                match crate::invoke::signup(server.clone(), req).await {
                    Ok(_) => set_is_signup.set(false),
                    Err(e) => set_status.set(format!("Error: {}", e)),
                }
            } else {
                // Login
                let req = crate::invoke::LoginRequest { username: user.clone(), password: pass };
                match crate::invoke::login(server.clone(), req).await {
                    Ok(res) => {
                        if let Some(token) = res.token {
                            set_status.set("Syncing Device...".into());
                            
                            // 1. Get or Generate Hardware ID
                            let mut config = crate::invoke::get_config().await.unwrap_or_default();
                            let hid = config.hardware_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                            
                            // 2. Get Hostname
                            let hostname = crate::invoke::get_hostname().await.unwrap_or_else(|_| "Unknown Device".to_string());
                            
                            // 3. Generate Keys if missing
                            let (pk, sk) = if let (Some(pk), Some(sk)) = (config.public_key.clone(), config.private_key.clone()) {
                                (pk, sk)
                            } else {
                                let keys = crate::invoke::generate_wg_keys().await.unwrap();
                                (keys.public_key, keys.private_key)
                            };

                            // Register this device to the user using Hardware ID
                            match crate::invoke::register_device(server.clone(), token.clone(), hostname.clone(), hid.clone(), pk.clone()).await {
                                Ok(vip) => {
                                    config.server_url = Some(server);
                                    config.username = Some(user);
                                    config.token = Some(token);
                                    config.hardware_id = Some(hid);
                                    config.public_key = Some(pk);
                                    config.private_key = Some(sk);
                                    config.virtual_ip = Some(vip);
                                    
                                    let _ = crate::invoke::save_config(config).await;
                                    navigate("/", Default::default());
                                },
                                Err(e) => set_status.set(format!("Device Error: {}", e)),
                            }
                        }
                    },
                    Err(e) => set_status.set(format!("Login Failed: {}", e)),
                }
            }
        });
    };

    view! {
        <div class="card">
            <h1>{move || if is_signup.get() { "Create Account" } else { "Welcome Back" }}</h1>
            <div style="margin-top:20px">
                <label>"SERVER"</label>
                <input type="text" prop:value=server_url on:input=move |e| set_server_url.set(event_target_value(&e)) />
                
                <label>"USERNAME"</label>
                <input type="text" on:input=move |e| set_username.set(event_target_value(&e)) />
                
                <label>"PASSWORD"</label>
                <input type="password" on:input=move |e| set_password.set(event_target_value(&e)) />
                
                <button on:click=on_submit>{move || if is_signup.get() { "Sign Up" } else { "Log In" }}</button>
                
                <p class="status" style="cursor:pointer; text-decoration:underline" on:click=move |_| set_is_signup.set(!is_signup.get())>
                    {move || if is_signup.get() { "Already have an account? Login" } else { "Don't have an account? Sign up" }}
                </p>
                <p class="status">{status}</p>
            </div>
        </div>
    }
}

#[component]
fn FileBrowser() -> impl IntoView {
    let navigate = use_navigate();
    let params = leptos_router::hooks::use_params_map();
    let ip = move || params.with(|p| p.get("ip").map(|s| s.to_string()).unwrap_or_default());
    let (path, set_path) = signal(".".to_string());

    let files = LocalResource::new(move || {
        let it = ip();
        let p = path.get();
        async move {
            crate::invoke::list_remote_files(it, p).await
        }
    });

    view! {
        <div class="card">
            <h2>"Files on " {ip}</h2>
            <Suspense fallback=|| "Loading...">
                {move || match files.get() {
                    None => view! { <p>"Loading..."</p> }.into_any(),
                    Some(data) => match (*data).clone() {
                        Ok(items) => view! {
                            <div style="margin-top:20px">
                                {items.into_iter().map(|f| {
                                    let f_path = f.path.clone();
                                    view! {
                                        <div class="device-item">
                                            <span>{if f.is_dir { "📁 " } else { "📄 " }}{f.name}</span>
                                            {if f.is_dir {
                                                view! { <button class="btn-sm" on:click=move |_| set_path.set(f_path.clone())>"Open"</button> }.into_any()
                                            } else {
                                                view! { <span class="status">{f.size} "B"</span> }.into_any()
                                            }}
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any(),
                        Err(e) => view! { <p> "Error: " {e} </p> }.into_any(),
                    }
                }}
            </Suspense>
            <button on:click=move |_| { navigate("/", Default::default()); }>"Back"</button>
        </div>
    }
}
