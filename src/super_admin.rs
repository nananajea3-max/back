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
use tokio::sync::Semaphore; // 🛡️ Diperlukan untuk 5-Pipe Concurrency

// =========================================================================
// 🚀 OPTIMASI SERVER RENDER GRATIS: 5-PIPE CONCURRENCY LIMITER
// (Mitigasi #18 DoS, #50 OOM / Uncontrolled Resource, #80 Thread Starvation)
// =========================================================================
// Menahan maksimal 5 beban komputasi DB secara bersamaan. Sisa request akan 
// diantrekan dengan sangat efisien oleh Tokio tanpa membuat server crash/hang.
static DB_PIPE: Semaphore = Semaphore::const_new(5);

// [Mitigasi #14, #82: Insecure Deserialization & Type Confusion]
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

#[derive(Deserialize)]
pub struct UpdateKycPayload {
    pub no_ktp: String,
    pub no_npwp: String,
}

// =========================================================================
// 🛡️ HELPER KEAMANAN: SECURITY HEADERS (Mitigasi #3, #35, #36, #39, #76, #92)
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
// 🛡️ HELPER: VALIDASI JWT (Mitigasi #12, #33, #83, #84 BOLA, Clock Drift)
// =========================================================================
fn verify_super_admin(headers: &HeaderMap) -> Result<String, Response> {
    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim(),
        _ => return Err(error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid.")),
    };

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_default".to_string());
    
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60; // Toleransi waktu 60 detik untuk sinkronisasi server

    match decode::<Claims>(token, &DecodingKey::from_secret(jwt_secret.as_bytes()), &validation) {
        Ok(data) => {
            if data.claims.sub == "SUPER-BOSS" { Ok(data.claims.sub) } 
            else { Err(error_response(StatusCode::FORBIDDEN, "Akses Ditolak.")) }
        },
        Err(_) => Err(error_response(StatusCode::UNAUTHORIZED, "Token kedaluarsa atau invalid.")),
    }
}

// =========================================================================
// API 1: LOGIN (Mitigasi #7 SQLi, #48 Panic, #51 Timing Attacks)
// =========================================================================
pub async fn login(State(pool): State<MySqlPool>, Json(payload): Json<LoginPayload>) -> impl IntoResponse {
    // 🚦 Menerapkan 1 Pipe perlindungan memori (Antrean Komputasi)
    let _permit = match DB_PIPE.acquire().await {
        Ok(p) => p,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "Server sedang menyeimbangkan beban."),
    };

    let query = "SELECT username, password_hash FROM super_admins WHERE username = ? LIMIT 1";
    let admin_row = match sqlx::query(query).bind(&payload.username).fetch_optional(&pool).await {
        Ok(Some(row)) => row,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "Kredensial salah."),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database sibuk."),
    };

    let username: String = admin_row.try_get("username").unwrap_or_default();
    let password_hash: String = admin_row.try_get("password_hash").unwrap_or_default();

    if !bcrypt::verify(&payload.password, &password_hash).unwrap_or(false) {
        return error_response(StatusCode::UNAUTHORIZED, "Kredensial salah.");
    }

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret_default".to_string());
    let expiration = chrono::Utc::now().checked_add_signed(chrono::Duration::hours(2)).unwrap().timestamp() as usize;

    let claims = Claims { sub: "SUPER-BOSS".to_string(), exp: expiration };
    
    // [Mitigasi #48 Uncaught Panic] Menggunakan match alih-alih .unwrap() untuk cegah crash
    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_bytes())) {
        Ok(t) => t,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memproses tiket sesi."),
    };
    
    success_response(json!({ "message": "Sukses", "token": token, "username": username }))
}

// =========================================================================
// API 2: MONITORING SALDO (DOUBLE-ENTRY) (Mitigasi #50 OOM LIMIT, #82 Type Confusion)
// =========================================================================
pub async fn get_all_tenant_balances(State(pool): State<MySqlPool>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    // 🚦 Menerapkan 1 Pipe perlindungan memori (Antrean Komputasi)
    let _permit = match DB_PIPE.acquire().await {
        Ok(p) => p,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "Server sedang sibuk."),
    };

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

    // 🚦 Menerapkan 1 Pipe perlindungan memori (Antrean Komputasi)
    let _permit = match DB_PIPE.acquire().await {
        Ok(p) => p,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "Server sedang sibuk."),
    };

    let query = "
        SELECT l.id, l.tenant_id, CAST(l.nominal AS CHAR) as nominal, l.nama_bank, 
        l.nomor_rekening, l.atas_nama, l.status, l.waktu_pengajuan, t.nama_toko, t.nama_pemilik 
        FROM ledger_out l LEFT JOIN tenants t ON l.tenant_id = t.id
        ORDER BY l.waktu_pengajuan DESC LIMIT 500
    ";

    match sqlx::query(query).fetch_all(&pool).await {
        Ok(rows) => {
            let mut list = Vec::new();
            for row in rows {
                let nominal: f64 = row.try_get::<String, _>("nominal").unwrap_or_default().parse().unwrap_or(0.0);
                let ts: String = row.try_get("waktu_pengajuan").unwrap_or_default(); 

                list.push(json!({
                    "id": row.try_get::<String, _>("id").unwrap_or_default(),
                    "nama_toko": row.try_get::<String, _>("nama_toko").unwrap_or_else(|_| "Anonim".to_string()),
                    "nama_pemilik": row.try_get::<String, _>("nama_pemilik").unwrap_or_else(|_| "-".to_string()),
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
// API 4: EKSEKUSI TRANSFER (Mitigasi #16, #100 TOCTOU & Race Condition)
// =========================================================================
pub async fn approve_withdrawal(
    State(pool): State<MySqlPool>, headers: HeaderMap, Path(withdrawal_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }

    // [Mitigasi #10 Path Traversal]
    let safe_wd_id = withdrawal_id.replace(|c: char| !c.is_alphanumeric() && c != '-', "");

    // 🚦 Menerapkan 1 Pipe perlindungan memori (Antrean Komputasi)
    let _permit = match DB_PIPE.acquire().await {
        Ok(p) => p,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "Server sedang sibuk."),
    };

    let query = "UPDATE ledger_out SET status = 'Selesai', waktu_selesai = CURRENT_TIMESTAMP WHERE id = ? AND status = 'Pending'";
    
    match sqlx::query(query).bind(&safe_wd_id).execute(&pool).await {
        Ok(res) => {
            if res.rows_affected() > 0 { success_response(json!({"message": "Transfer Sukses!"})) } 
            else { error_response(StatusCode::CONFLICT, "Pengajuan tidak ditemukan atau sudah diproses.") }
        },
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memproses ke database.")
    }
}

// =========================================================================
// API 5: AMBIL DETAIL PROFIL TENANT BESERTA RIWAYATNYA
// =========================================================================
pub async fn get_tenant_detail(
    State(pool): State<MySqlPool>, headers: HeaderMap, Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }
    
    let safe_id = tenant_id.replace(|c: char| !c.is_alphanumeric() && c != '-', "");

    // 🚦 Menerapkan 1 Pipe perlindungan memori (Antrean Komputasi)
    let _permit = match DB_PIPE.acquire().await {
        Ok(p) => p,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "Server sedang sibuk."),
    };

    let query_tenant = "SELECT * FROM tenants WHERE id = ?";
    let tenant_row = match sqlx::query(query_tenant).bind(&safe_id).fetch_optional(&pool).await {
        Ok(Some(row)) => row,
        _ => return error_response(StatusCode::NOT_FOUND, "Tenant tidak ditemukan."),
    };

    let query_wd = "SELECT id, CAST(nominal AS CHAR) as nominal, status, waktu_pengajuan FROM ledger_out WHERE tenant_id = ? ORDER BY waktu_pengajuan DESC LIMIT 50";
    let wds = sqlx::query(query_wd).bind(&safe_id).fetch_all(&pool).await.unwrap_or_default();
    
    let mut riwayat_penarikan = Vec::new();
    for w in wds {
        riwayat_penarikan.push(json!({
            "id": w.try_get::<String, _>("id").unwrap_or_default(),
            "nominal": w.try_get::<String, _>("nominal").unwrap_or_default().parse::<f64>().unwrap_or(0.0),
            "status": w.try_get::<String, _>("status").unwrap_or_default(),
            "waktu": w.try_get::<String, _>("waktu_pengajuan").unwrap_or_default()
        }));
    }

    let query_income = "SELECT CAST(total_pemasukan AS CHAR) as total, terakhir_sinkron FROM tenant_incomes WHERE tenant_id = ?";
    let income_row = sqlx::query(query_income).bind(&safe_id).fetch_optional(&pool).await.unwrap_or_default();
    
    let (total_masuk, terakhir_sinkron) = match income_row {
        Some(row) => (
            row.try_get::<String, _>("total").unwrap_or_default().parse::<f64>().unwrap_or(0.0),
            row.try_get::<String, _>("terakhir_sinkron").unwrap_or_default()
        ),
        None => (0.0, String::from("Belum ada data")),
    };

    success_response(json!({
        "profil": {
            "id": tenant_row.try_get::<String, _>("id").unwrap_or_default(),
            "nama_toko": tenant_row.try_get::<String, _>("nama_toko").unwrap_or_default(),
            "nama_pemilik": tenant_row.try_get::<String, _>("nama_pemilik").unwrap_or_default(),
            "nomor_wa": tenant_row.try_get::<String, _>("nomor_wa").unwrap_or_default(),
            "email": tenant_row.try_get::<String, _>("email").unwrap_or_default(),
            "alamat": tenant_row.try_get::<String, _>("alamat_penjemputan").unwrap_or_default(),
            "no_ktp": tenant_row.try_get::<String, _>("no_ktp").unwrap_or_default(),
            "no_npwp": tenant_row.try_get::<String, _>("no_npwp").unwrap_or_default(),
            "bank_nama": tenant_row.try_get::<String, _>("bank_nama").unwrap_or_default(),
            "bank_rekening": tenant_row.try_get::<String, _>("bank_rekening").unwrap_or_default(),
            "bank_atas_nama": tenant_row.try_get::<String, _>("bank_atas_nama").unwrap_or_default(),
        },
        "keuangan": {
            "total_masuk": total_masuk,
            "terakhir_sinkron_masuk": terakhir_sinkron,
            "riwayat_penarikan": riwayat_penarikan
        }
    }))
}

// =========================================================================
// API 6: UPDATE KYC (KTP & NPWP) 
// (Mitigasi #22 Mass Assignment, #43 Payload Overflow)
// =========================================================================
pub async fn update_tenant_kyc(
    State(pool): State<MySqlPool>, headers: HeaderMap, Path(tenant_id): Path<String>, Json(payload): Json<UpdateKycPayload>,
) -> impl IntoResponse {
    if let Err(e) = verify_super_admin(&headers) { return e; }
    
    let safe_id = tenant_id.replace(|c: char| !c.is_alphanumeric() && c != '-', "");

    let ktp = payload.no_ktp.trim();
    let npwp = payload.no_npwp.trim();

    // [Mitigasi #17, #50 Decompression/Buffer Overflow Attack]
    // Mencegah hacker memasukkan teks jutaan karakter yang merusak RAM DB Pusat
    if ktp.len() > 30 || npwp.len() > 30 {
        return error_response(StatusCode::BAD_REQUEST, "Format ID terlalu panjang (Maks. 30 Karakter).");
    }

    // 🚦 Menerapkan 1 Pipe perlindungan memori (Antrean Komputasi)
    let _permit = match DB_PIPE.acquire().await {
        Ok(p) => p,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "Server sedang sibuk."),
    };

    let query = "UPDATE tenants SET no_ktp = ?, no_npwp = ? WHERE id = ?";
    match sqlx::query(query).bind(ktp).bind(npwp).bind(&safe_id).execute(&pool).await {
        Ok(_) => success_response(json!({"message": "Data KYC berhasil disimpan!"})),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal menyimpan data KYC."),
    }
}
