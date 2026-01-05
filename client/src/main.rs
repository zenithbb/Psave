use leptos::prelude::*;
use leptos::mount::mount_to_body;

mod app;
mod invoke;
use app::App;

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App/> })
}
