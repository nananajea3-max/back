use axum::{
    routing::{get, post},
    Router,
};
use sqlx::mysql::MySqlPoolOptions;
use std::env;
use tower_http::cors::{Any, CorsLayer};
use axum::http::Method;

// Memanggil file super_admin.rs yang telah Anda buat sebelumnya
mod super_admin; 

#[tokio::main]
async fn main() {
    // Render menggunakan env var PORT secara dinamis. Default 8000 untuk lokal.
    let port = env::var("PORT").unwrap_or_else(|_| "8000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    // MENGAMBIL KONEKSI DATABASE KHUSUS SUPER ADMIN
    let db_url = env::var("DATABASE_URL")
        .expect("⚠️ FATAL: DATABASE_URL (TiDB db_superadmin) belum dimasukkan di Environment Variables Render!");

    println!("🔄 Menghubungkan ke Bank Sentral (TiDB db_superadmin)...");
    
    // Konfigurasi koneksi (Dibatasi maks 10 koneksi agar Render Gratis tidak OOM/Tumbang)
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .expect("❌ Gagal terhubung ke Database Bank Sentral!");
        
    println!("✅ Terhubung ke Bank Sentral!");

    // 🛡️ SECURITY: Konfigurasi CORS 
    let cors = CorsLayer::new()
        .allow_origin(Any) // Saat Live, ubah "Any" dengan domain Vercel Super Admin Anda
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    // =========================================================================
    // 🚦 ROUTER KHUSUS SUPER ADMIN (Tertutup & Terisolasi)
    // =========================================================================
    let app = Router::new()
        .route("/api/super/balances", get(super_admin::get_all_tenant_balances))
        .route("/api/super/withdrawals", get(super_admin::get_all_withdrawals))
        .route("/api/super/withdrawals/:id/approve", post(super_admin::approve_withdrawal))
        .route("/api/super/tenants", post(super_admin::register_tenant_manual))
        .layer(cors)
        .with_state(pool);

    println!("🚀 Server Pusat Bakoel Super Admin berjalan di {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}