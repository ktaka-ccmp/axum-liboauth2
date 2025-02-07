use axum::{routing::get, Router};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use axum_server::tls_rustls::RustlsConfig;
use std::{net::SocketAddr, path::PathBuf};
use tokio::task::JoinHandle;

use dotenv::dotenv;

use liboauth2::oauth2::app_state_init;

mod handlers;
use handlers::{
    get_authorized, google_auth, index, logout, popup_close, post_authorized, protected,
};

#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let oauth2_state = app_state_init().await.unwrap_or_else(|e| {
        eprintln!("Failed to initialize AppState: {e}");
        std::process::exit(1);
    });

    // let oauth2_state = liboauth2::AppState::new().await?;

    // CorsLayer is not needed unless frontend is coded in JavaScript and is hosted on a different domain.

    // let allowed_origin = env::var("ORIGIN").expect("Missing ORIGIN!");
    // let allowed_origin = format!("http://localhost:3000");
    // let allowed_origin = format!("https://accounts.google.com");

    // let cors = CorsLayer::new()
    //     .allow_origin(HeaderValue::from_str(&allowed_origin).unwrap())
    //     .allow_methods([http::Method::GET, http::Method::POST])
    //     .allow_credentials(true);

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/google", get(google_auth))
        .route(
            "/auth/authorized",
            get(get_authorized).post(post_authorized),
        )
        .route("/popup_close", get(popup_close))
        .route("/logout", get(logout))
        .route("/protected", get(protected))
        // .layer(cors)
        .with_state(oauth2_state);

    let ports = Ports {
        http: 3001,
        https: 3443,
    };

    let http_server = spawn_http_server(ports.http, app.clone());
    let https_server = spawn_https_server(ports.https, app);

    // Wait for both servers to complete (which they never will in this case)
    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}

fn spawn_http_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::debug!("HTTP server listening on {}:{}", addr, port);
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

fn spawn_https_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let config = RustlsConfig::from_pem_file(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("self_signed_certs")
                .join("cert.pem"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("self_signed_certs")
                .join("key.pem"),
        )
        .await
        .unwrap();

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::debug!("HTTPS server listening on {}:{}", addr, port);
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}
