use axum::{
    routing::{get, post},
    Router,
};
use axum::http::{Method, header, HeaderValue};
use sqlx::mysql::MySqlPoolOptions;
use std::env;
use tower_http::{
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
};

// Modul endpoint super admin
mod super_admin; 

#[tokio::main]
async fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "8000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let db_url = env::var("DATABASE_URL")
        .expect("⚠️ FATAL: DATABASE_URL belum diatur!");

    println!("🔄 Menghubungkan ke Bank Sentral (TiDB)...");
    
    // [Mitigasi #50, #80: OOM Attack & Thread Exhaustion]
    // Membatasi koneksi maksimal untuk menghindari kehabisan memori server Render
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .expect("❌ Gagal terhubung ke Database Bank Sentral!");
        
    println!("✅ Terhubung ke Bank Sentral!");

    // [Mitigasi #20: CORS Misconfiguration]
    // Saat produksi, ganti 'Any' dengan URL spesifik Vercel Anda
    let cors = CorsLayer::new()
        .allow_origin(Any) 
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    // [Mitigasi #3, #39, #92: Clickjacking, MIME Sniffing, XS-Leaks]
    // Menerapkan Security Headers secara global pada aplikasi
    let app = Router::new()
        .route("/api/super/login", post(super_admin::login))
        .route("/api/super/balances", get(super_admin::get_all_tenant_balances))
        .route("/api/super/withdrawals", get(super_admin::get_all_withdrawals))
        .route("/api/super/withdrawals/:id/approve", post(super_admin::approve_withdrawal))
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .with_state(pool);

    println!("🚀 Server Pusat Bakoel Super Admin berjalan di {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
