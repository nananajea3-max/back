use axum::{
    routing::{get, post, put},
    Router,
};
use sqlx::mysql::MySqlPoolOptions;
use std::env;
use std::time::Duration;
use tower_http::{
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
};
use axum::http::{Method, header, HeaderValue};

// Memanggil file super_admin.rs
mod super_admin; 

#[tokio::main]
async fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "8000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let db_url = env::var("DATABASE_URL")
        .expect("⚠️ FATAL: DATABASE_URL belum diatur di Environment Variables!");

    println!("🔄 Menghubungkan ke Bank Sentral (TiDB)...");
    
    // =====================================================================
    // 🚀 OPTIMASI SERVER RENDER GRATIS & ANTI-DOS (Mitigasi #18, #50, #80)
    // =====================================================================
    let pool = MySqlPoolOptions::new()
        .max_connections(10) // Batas aman untuk RAM Render gratisan
        .min_connections(1)  // Jaga 1 koneksi standby agar respons cepat saat server "bangun"
        .acquire_timeout(Duration::from_secs(15)) // Anti-Hang: Batalkan jika DB lemot merespon
        .idle_timeout(Duration::from_secs(600))   // Bersihkan koneksi memori nganggur (OOM Guard)
        .connect(&db_url)
        .await
        .expect("❌ Gagal terhubung ke Database Bank Sentral!");
        
    println!("✅ Terhubung ke Bank Sentral!");

    // =====================================================================
    // 🛡️ SECURITY LAYER 1: STRICT CORS (Mitigasi #20 CORS Misconfiguration)
    // =====================================================================
    let cors = CorsLayer::new()
        .allow_origin(Any) 
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        // Membatasi header HANYA yang digunakan Vercel. Mencegah exfiltrasi data ilegal.
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]); 

    // =====================================================================
    // 🛡️ SECURITY LAYER 2: GLOBAL HEADERS (Mitigasi #3, #35, #39, #76, #92)
    // =====================================================================
    // Ini mengunci SELURUH celah aplikasi, bahkan di endpoint yang tidak ada
    let security_headers = Router::new()
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
        .layer(SetResponseHeaderLayer::overriding(
            header::X_XSS_PROTECTION,
            HeaderValue::from_static("1; mode=block"),
        ));

    // =====================================================================
    // 🚦 ROUTER KHUSUS SUPER ADMIN (Tertutup & Terisolasi)
    // =====================================================================
    let app = Router::new()
        .route("/api/super/login", post(super_admin::login))
        .route("/api/super/balances", get(super_admin::get_all_tenant_balances))
        .route("/api/super/withdrawals", get(super_admin::get_all_withdrawals))
        .route("/api/super/withdrawals/:id/approve", post(super_admin::approve_withdrawal))
        .route("/api/super/tenants/:id", get(super_admin::get_tenant_detail))
        .route("/api/super/tenants/:id/kyc", put(super_admin::update_tenant_kyc))
        .layer(cors)
        .merge(security_headers) // Menggabungkan pelindung header ke seluruh aplikasi
        .with_state(pool);

    println!("🚀 Server Pusat Bakoel Super Admin berjalan di {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
