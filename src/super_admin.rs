use axum::{
    extract::{Path, State, Json},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use std::env;
use jsonwebtoken::{decode, encode, Header, EncodingKey, DecodingKey, Validation, Algorithm};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password:  String,
}

// =========================================================================
// 🛡️ HELPER: KENDALI RESPONSE (Mitigasi Web Cache Poisoning & Deception)
// =========================================================================
fn success_response(payload: Value) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"));
    (StatusCode::OK, headers, Json(payload)).into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let error_json = json!({ "error": message });
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate"));
    (status, headers, Json(error_json)).into_response()
}

// =========================================================================
// 🛡️ HELPER: VALIDASI JWT (Mitigasi BOLA/IDOR & Clock Drift)
// =========================================================================
fn verify_super_admin(headers: &HeaderMap) -> Result<String, Response> {
    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim(),
        _ => return Err(error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid.")),
    };

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_default".to_string());
    
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60; // [Mitigasi #83: Time Manipulation/Clock Drift]

    match decode::<Claims>(token, &DecodingKey::from_secret(jwt_secret.as_bytes()), &validation) {
        Ok(data) => {
            if data.claims.sub == "SUPER-BOSS" { Ok(data.claims.sub) } 
            else { Err(error_response(StatusCode::FORBIDDEN, "Akses Ditolak.")) }
        },
        Err(_) => Err(error_response(StatusCode::UNAUTHORIZED, "Token kedaluarsa atau invalid.")),
    }
}

// =========================================================================
// API 1: LOGIN BERBASIS DATABASE 
// =========================================================================
pub async fn login(
    State(pool): State<MySqlPool>,
    Json(payload): Json<LoginPayload>,
) -> impl IntoResponse {
    
    // [Mitigasi #7: SQL Injection] - Parameterized query
    let query = "SELECT username, password_hash FROM super_admins WHERE username = ? LIMIT 1";
    let admin_row = match sqlx::query(query).bind(&payload.username).fetch_optional(&pool).await {
        Ok(Some(row)) => row,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "Kredensial salah."),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database sibuk."),
    };

    let username: String = admin_row.try_get("username").unwrap_or_default();
    let password_hash: String = admin_row.try_get("password_hash").unwrap_or_default();

    // [Mitigasi #51: Timing Attacks] - bcrypt::verify berjalan secara konstan (constant-time)
    if !bcrypt::verify(&payload.password, &password_hash).unwrap_or(false) {
        return error_response(StatusCode::UNAUTHORIZED, "Kredensial salah.");
    }

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_default".to_string());
    let expiration = chrono::Utc::now().checked_add_signed(chrono::Duration::hours(2)).unwrap().timestamp() as usize;

    let claims = Claims { sub: "SUPER-BOSS".to_string(), exp: expiration };
    
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_bytes())).unwrap();
    success_response(json!({ "message": "Sukses", "token": token, "username": username }))
}

// =========================================================================
// API 2: MONITORING SALDO (DOUBLE-ENTRY CALCULATION)
// =========================================================================
pub async fn get_all_tenant_balances(State(pool): State<MySqlPool>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    // [Mitigasi #82: Type Confusion] Casting DECIMAL ke CHAR dengan aman
    // [Mitigasi #50: Resource Exhaustion] LIMIT 1000 ditambahkan
    let query = "
        SELECT 
            t.id AS tenant_id, t.nama_toko, t.nama_pemilik, t.nomor_wa,
            CAST(COALESCE(i.total_pemasukan, 0) AS CHAR) AS total_masuk,
            CAST((SELECT COALESCE(SUM(nominal), 0) FROM ledger_out WHERE tenant_id = t.id AND status IN ('Pending', 'Selesai')) AS CHAR) AS total_keluar
        FROM tenants t
        LEFT JOIN tenant_incomes i ON t.id = i.tenant_id
        ORDER BY t.created_at DESC LIMIT 1000
    ";

    match sqlx::query(query).fetch_all(&pool).await {
        Ok(rows) => {
            let mut result = Vec::new();
            for row in rows {
                let t_masuk: f64 = row.try_get::<String, _>("total_masuk").unwrap_or_default().parse().unwrap_or(0.0);
                let t_keluar: f64 = row.try_get::<String, _>("total_keluar").unwrap_or_default().parse().unwrap_or(0.0);
                
                result.push(json!({
                    "tenant_id": row.try_get::<String, _>("tenant_id").unwrap_or_default(),
                    "nama_toko": row.try_get::<String, _>("nama_toko").unwrap_or_default(),
                    "nama_pemilik": row.try_get::<String, _>("nama_pemilik").unwrap_or_default(),
                    "no_wa": row.try_get::<String, _>("nomor_wa").unwrap_or_default(),
                    "saldo_tersedia": t_masuk - t_keluar,
                    "total_masuk": t_masuk,
                    "total_ditarik": t_keluar
                }));
            }
            success_response(json!(result))
        },
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memuat saldo.")
    }
}

// =========================================================================
// API 3: ANTREAN PENARIKAN
// =========================================================================
pub async fn get_all_withdrawals(State(pool): State<MySqlPool>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    let query = "
        SELECT l.id, l.tenant_id, CAST(l.nominal AS CHAR) as nominal, l.nama_bank, 
        l.nomor_rekening, l.atas_nama, l.status, l.waktu_pengajuan, t.nama_toko 
        FROM ledger_out l LEFT JOIN tenants t ON l.tenant_id = t.id
        ORDER BY l.waktu_pengajuan DESC LIMIT 500
    ";

    match sqlx::query(query).fetch_all(&pool).await {
        Ok(rows) => {
            let mut list = Vec::new();
            for row in rows {
                let nominal: f64 = row.try_get::<String, _>("nominal").unwrap_or_default().parse().unwrap_or(0.0);
                let ts: String = row.try_get("waktu_pengajuan").unwrap_or_default(); // Simplifikasi

                list.push(json!({
                    "id": row.try_get::<String, _>("id").unwrap_or_default(),
                    "nama_toko": row.try_get::<String, _>("nama_toko").unwrap_or_else(|_| "Anonim".to_string()),
                    "nominal": nominal, "status": row.try_get::<String, _>("status").unwrap_or_default(),
                    "bank": row.try_get::<String, _>("nama_bank").unwrap_or_default(),
                    "rekening": row.try_get::<String, _>("nomor_rekening").unwrap_or_default(),
                    "atas_nama": row.try_get::<String, _>("atas_nama").unwrap_or_default(), "tanggal": ts
                }));
            }
            success_response(json!(list))
        },
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memuat antrean."),
    }
}

// =========================================================================
// API 4: EKSEKUSI TRANSFER (TRANSAKSI AMAN)
// =========================================================================
pub async fn approve_withdrawal(
    State(pool): State<MySqlPool>,
    headers: HeaderMap,
    Path(withdrawal_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    // [Mitigasi #10, #23: Path Traversal & Parameter Tampering] Sanitasi ID input
    let safe_wd_id = withdrawal_id.replace(|c: char| !c.is_alphanumeric() && c != '-', "");

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal inisiasi DB."),
    };

    // [Mitigasi #16, #100: TOCTOU & Race Condition di State Machines] SELECT ... FOR UPDATE
    let lock_query = "SELECT status FROM ledger_out WHERE id = ? FOR UPDATE";
    let current_status: Option<String> = match sqlx::query_scalar(lock_query).bind(&safe_wd_id).fetch_optional(&mut *tx).await {
        Ok(Some(status)) => Some(status),
        _ => { let _ = tx.rollback().await; return error_response(StatusCode::NOT_FOUND, "ID Invalid."); }
    };

    if current_status.unwrap() != "Pending" {
        let _ = tx.rollback().await;
        return error_response(StatusCode::CONFLICT, "Sudah diproses.");
    }

    let update_query = "UPDATE ledger_out SET status = 'Selesai', waktu_selesai = CURRENT_TIMESTAMP WHERE id = ?";
    if sqlx::query(update_query).bind(&safe_wd_id).execute(&mut *tx).await.is_err() {
        let _ = tx.rollback().await;
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal update.");
    }

    if tx.commit().await.is_err() { return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal commit."); }

    success_response(json!({"message": "Transfer Sukses!"}))
}
