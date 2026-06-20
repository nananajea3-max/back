use axum::{
    routing::{get, post, put}, // 1. Tambahkan izin 'put' di sini
    Router,
};
use sqlx::mysql::MySqlPoolOptions;
use std::env;
use tower_http::cors::{Any, CorsLayer};
use axum::http::Method;

// Memanggil file super_admin.rs
mod super_admin; 

#[tokio::main]
async fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "8000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let db_url = env::var("DATABASE_URL")
        .expect("⚠️ FATAL: DATABASE_URL belum diatur di Environment Variables!");

    println!("🔄 Menghubungkan ke Bank Sentral (TiDB)...");
    
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .expect("❌ Gagal terhubung ke Database Bank Sentral!");
        
    println!("✅ Terhubung ke Bank Sentral!");

    // 2. 🛡️ FIX CORS: Tambahkan Method::PUT agar Vercel diizinkan menyimpan data baru
    let cors = CorsLayer::new()
        .allow_origin(Any) 
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers(Any);

    // 3. DAFTARKAN SEMUA RUTE SECARA LENGKAP
    let app = Router::new()
        .route("/api/super/login", post(super_admin::login))
        .route("/api/super/balances", get(super_admin::get_all_tenant_balances))
        .route("/api/super/withdrawals", get(super_admin::get_all_withdrawals))
        .route("/api/super/withdrawals/:id/approve", post(super_admin::approve_withdrawal))
        // 👇 Dua rute profil dan KYC yang sebelumnya terlewat
        .route("/api/super/tenants/:id", get(super_admin::get_tenant_detail))
        .route("/api/super/tenants/:id/kyc", put(super_admin::update_tenant_kyc))
        .layer(cors)
        .with_state(pool);

    println!("🚀 Server Pusat Bakoel Super Admin berjalan di {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
