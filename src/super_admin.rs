use axum::{
    extract::{Path, State, Json},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use std::env;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    pub sub: String,
    pub exp: usize,
}

// =========================================================================
// 🛡️ HELPER KEAMANAN: SECURITY HEADERS (Anti Clickjacking, Cache Poisoning)
// =========================================================================
fn success_response(payload: Value) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("Strict-Transport-Security", HeaderValue::from_static("max-age=31536000; includeSubDomains"));
    
    (StatusCode::OK, headers, Json(payload)).into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let error_json = json!({ "error": message });
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate"));
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    
    (status, headers, Json(error_json)).into_response()
}

// =========================================================================
// 🛡️ HELPER KEAMANAN: HANYA SUPER ADMIN YANG BISA AKSES (Anti Privilege Escalation)
// =========================================================================
fn verify_super_admin(headers: &HeaderMap) -> Result<String, Response> {
    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim(),
        _ => return Err(error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid atau tidak ditemukan.")),
    };

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_default();
    if jwt_secret.is_empty() {
        return Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, "Kunci keamanan server belum dikonfigurasi."));
    }

    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60; // Toleransi waktu anti Clock Drift

    match decode::<Claims>(token, &DecodingKey::from_secret(jwt_secret.as_bytes()), &validation) {
        Ok(data) => {
            // 🚨 SANGAT PENTING: Ganti "SUPER-BOSS" dengan ID rahasia login Anda nanti
            if data.claims.sub == "SUPER-BOSS" { 
                Ok(data.claims.sub) 
            } else { 
                Err(error_response(StatusCode::FORBIDDEN, "Akses Ditolak: Anda Bukan Super Admin!")) 
            }
        },
        Err(_) => Err(error_response(StatusCode::UNAUTHORIZED, "Token kedaluarsa atau telah dimanipulasi.")),
    }
}

// =========================================================================
// API 1: PUSAT MONITORING SALDO (Melihat Saldo Seluruh Tenant)
// =========================================================================
pub async fn get_all_tenant_balances(State(pool): State<MySqlPool>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    // 🛡️ SQL AMAN: Kasting DECIMAL ke CHAR untuk anti Type Confusion / Uncaught Panic
    let query = "
        SELECT 
            t.id AS tenant_id, 
            t.nama_toko, 
            t.nama_pemilik,
            t.nomor_wa,
            t.no_ktp,
            CAST(COALESCE(i.total_pemasukan, 0) AS CHAR) AS total_masuk,
            CAST(
                (SELECT COALESCE(SUM(nominal), 0) 
                 FROM ledger_out 
                 WHERE tenant_id = t.id AND status IN ('Pending', 'Selesai')) 
            AS CHAR) AS total_keluar
        FROM tenants t
        LEFT JOIN tenant_incomes i ON t.id = i.tenant_id
        ORDER BY t.created_at DESC
        LIMIT 1000
    ";

    match sqlx::query(query).fetch_all(&pool).await {
        Ok(rows) => {
            let mut result = Vec::new();
            for row in rows {
                let id: String = row.try_get("tenant_id").unwrap_or_default();
                let toko: String = row.try_get("nama_toko").unwrap_or_default();
                let pemilik: String = row.try_get("nama_pemilik").unwrap_or_default();
                let wa: String = row.try_get("nomor_wa").unwrap_or_default();
                
                // Parsing aman dari String ke F64
                let t_masuk: f64 = row.try_get::<String, _>("total_masuk")
                    .unwrap_or_default().parse::<f64>().unwrap_or(0.0);
                let t_keluar: f64 = row.try_get::<String, _>("total_keluar")
                    .unwrap_or_default().parse::<f64>().unwrap_or(0.0);
                
                let saldo_asli = t_masuk - t_keluar;

                result.push(json!({
                    "tenant_id": id,
                    "nama_toko": toko,
                    "nama_pemilik": pemilik,
                    "no_wa": wa,
                    "saldo_tersedia": saldo_asli,
                    "total_masuk": t_masuk,
                    "total_ditarik": t_keluar
                }));
            }
            success_response(json!(result))
        },
        Err(e) => {
            println!("DB Error: {:?}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal menarik data pengawasan saldo.")
        }
    }
}

// =========================================================================
// API 2: LIHAT SEMUA PENGAJUAN PENARIKAN (PENDING & SELESAI)
// =========================================================================
pub async fn get_all_withdrawals(State(pool): State<MySqlPool>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    let query = "
        SELECT 
            l.id, l.tenant_id, CAST(l.nominal AS CHAR) as nominal, l.nama_bank, 
            l.nomor_rekening, l.atas_nama, l.status, l.waktu_pengajuan, t.nama_toko 
        FROM ledger_out l
        LEFT JOIN tenants t ON l.tenant_id = t.id
        ORDER BY l.waktu_pengajuan DESC
        LIMIT 500
    ";

    match sqlx::query(query).fetch_all(&pool).await {
        Ok(rows) => {
            let mut list = Vec::new();
            for row in rows {
                let nominal: f64 = row.try_get::<String, _>("nominal")
                    .unwrap_or_default().parse::<f64>().unwrap_or(0.0);

                // Konversi Timestamp aman
                let waktu_pengajuan_str = if let Ok(dt) = row.try_get::<chrono::DateTime<chrono::Utc>, _>("waktu_pengajuan") {
                    format!("{}Z", dt.format("%Y-%m-%dT%H:%M:%S.000"))
                } else if let Ok(ndt) = row.try_get::<chrono::NaiveDateTime, _>("waktu_pengajuan") {
                    format!("{}Z", ndt.format("%Y-%m-%dT%H:%M:%S.000"))
                } else {
                    row.try_get::<String, _>("waktu_pengajuan").unwrap_or_default()
                };

                list.push(json!({
                    "id": row.try_get::<String, _>("id").unwrap_or_default(),
                    "tenant_id": row.try_get::<String, _>("tenant_id").unwrap_or_default(),
                    "nama_toko": row.try_get::<String, _>("nama_toko").unwrap_or_else(|_| "Toko Tidak Diketahui".to_string()),
                    "nominal": nominal,
                    "status": row.try_get::<String, _>("status").unwrap_or_default(),
                    "bank": row.try_get::<String, _>("nama_bank").unwrap_or_default(),
                    "rekening": row.try_get::<String, _>("nomor_rekening").unwrap_or_default(),
                    "atas_nama": row.try_get::<String, _>("atas_nama").unwrap_or_default(),
                    "tanggal": waktu_pengajuan_str
                }));
            }
            success_response(json!(list))
        },
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal menarik antrean penarikan."),
    }
}

// =========================================================================
// API 3: EKSEKUSI TRANSFER (UBAH PENDING JADI SELESAI)
// 🛡️ ANTI TOCTOU (Time of Check to Time of Use)
// =========================================================================
pub async fn approve_withdrawal(
    State(pool): State<MySqlPool>,
    headers: HeaderMap,
    Path(withdrawal_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    // Sanitasi Path Variable (Anti SQLi / Path Traversal)
    let safe_wd_id = withdrawal_id.replace(|c: char| !c.is_alphanumeric() && c != '-', "");

    // 🛡️ Atomic Update: Pastikan hanya bisa update jika statusnya benar-benar "Pending"
    let query = "
        UPDATE ledger_out 
        SET status = 'Selesai', waktu_selesai = CURRENT_TIMESTAMP 
        WHERE id = ? AND status = 'Pending'
    ";
    
    match sqlx::query(query).bind(&safe_wd_id).execute(&pool).await {
        Ok(res) => {
            if res.rows_affected() > 0 {
                success_response(json!({"message": "Transfer Sukses! Status pencairan telah diubah menjadi Selesai."}))
            } else {
                error_response(StatusCode::CONFLICT, "Pengajuan tidak ditemukan atau sudah diproses sebelumnya.")
            }
        },
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Sistem Database sibuk. Gagal mengupdate status pencairan.")
    }
}

// =========================================================================
// API 4 (OPSIONAL): MENDAFTARKAN IDENTITAS TENANT BARU SECARA MANUAL
// =========================================================================
#[derive(Deserialize)]
pub struct NewTenantPayload {
    pub tenant_id: String,
    pub nama_toko: String,
    pub nama_pemilik: String,
    pub nomor_wa: String,
    pub no_ktp: Option<String>,
    pub no_npwp: Option<String>,
}

pub async fn register_tenant_manual(
    State(pool): State<MySqlPool>,
    headers: HeaderMap,
    Json(payload): Json<NewTenantPayload>,
) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    let query = "
        INSERT INTO tenants (id, nama_toko, nama_pemilik, nomor_wa, no_ktp, no_npwp)
        VALUES (?, ?, ?, ?, ?, ?)
    ";

    match sqlx::query(query)
        .bind(&payload.tenant_id).bind(&payload.nama_toko).bind(&payload.nama_pemilik)
        .bind(&payload.nomor_wa).bind(payload.no_ktp).bind(payload.no_npwp)
        .execute(&pool).await 
    {
        Ok(_) => success_response(json!({"message": format!("Tenant {} berhasil diregistrasi ke Bank Sentral.", payload.nama_toko)})),
        Err(_) => error_response(StatusCode::CONFLICT, "Tenant ID tersebut sudah terdaftar di sistem.")
    }
}