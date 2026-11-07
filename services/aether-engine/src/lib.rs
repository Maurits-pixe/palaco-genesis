use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State, rejection::JsonRejection},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

pub const MAX_PLAINTEXT: usize = 16 * 1024;
pub const MAX_BODY: usize = 64 * 1024;

pub struct Config {
    token: String,
    key: [u8; 32],
    db: PathBuf,
    port: u16,
}

impl Config {
    pub fn from_env() -> Result<Self, &'static str> {
        Self::parse(
            env::var("AETHER_TOKEN").ok(),
            env::var("AETHER_KEY_HEX").ok(),
            optional_env("AETHER_DB")?,
            optional_env("AETHER_PORT")?,
        )
    }

    fn parse(
        token: Option<String>,
        key: Option<String>,
        db: Option<String>,
        port: Option<String>,
    ) -> Result<Self, &'static str> {
        let token = token.ok_or("AETHER_TOKEN is required")?;
        if !(32..=4096).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(
                "AETHER_TOKEN must contain 32 to 4096 printable ASCII characters without whitespace",
            );
        }
        let key = key.ok_or("AETHER_KEY_HEX is required")?;
        if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("AETHER_KEY_HEX must contain exactly 64 hexadecimal characters");
        }
        let mut decoded = [0; 32];
        for (byte, pair) in decoded.iter_mut().zip(key.as_bytes().as_chunks::<2>().0) {
            let digit = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
            *byte = digit(pair[0]) * 16 + digit(pair[1]);
        }
        let db = db.unwrap_or_else(|| "aether.db".into());
        if db.trim().is_empty() || db.contains('\0') {
            return Err("AETHER_DB must be a nonempty database path");
        }
        let port = match port {
            Some(port) => port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or("AETHER_PORT must be an integer between 1 and 65535")?,
            None => 8787,
        };
        Ok(Self {
            token,
            key: decoded,
            db: db.into(),
            port,
        })
    }

    pub fn address(&self) -> SocketAddr {
        (Ipv4Addr::LOCALHOST, self.port).into()
    }
}

fn optional_env(name: &str) -> Result<Option<String>, &'static str> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err("configuration must contain valid Unicode"),
    }
}

struct Store {
    connection: Connection,
    key: LessSafeKey,
    rng: SystemRandom,
}

impl Store {
    fn open(path: &std::path::Path, key: &[u8; 32]) -> Result<Self, ApiError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|_| ApiError::Internal)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| ApiError::Internal)?;
        }
        let connection = Connection::open(path).map_err(|_| ApiError::Internal)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ApiError::Internal)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY NOT NULL,
                    nonce BLOB NOT NULL UNIQUE CHECK(length(nonce) = 12),
                    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 16400)
                );",
            )
            .map_err(|_| ApiError::Internal)?;
        let key = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| ApiError::Internal)?;
        Ok(Self {
            connection,
            key: LessSafeKey::new(key),
            rng: SystemRandom::new(),
        })
    }

    fn insert(&mut self, plaintext: &str) -> Result<String, ApiError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(ApiError::TooLarge);
        }
        let id = random_id(&self.rng)?;
        let mut nonce = [0; 12];
        self.rng.fill(&mut nonce).map_err(|_| ApiError::Internal)?;
        let mut ciphertext = plaintext.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(id.as_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| ApiError::Internal)?;
        // The UNIQUE nonce constraint rejects an RNG collision before persistence.
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApiError::Internal)?;
        transaction
            .execute(
                "INSERT INTO records (id, nonce, ciphertext) VALUES (?1, ?2, ?3)",
                params![id, nonce.as_slice(), ciphertext],
            )
            .map_err(|_| ApiError::Internal)?;
        transaction.commit().map_err(|_| ApiError::Internal)?;
        Ok(id)
    }

    fn get(&self, id: &str) -> Result<Record, ApiError> {
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::NotFound);
        }
        let (nonce, mut ciphertext): (Vec<u8>, Vec<u8>) = self
            .connection
            .query_row(
                "SELECT nonce, ciphertext FROM records WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::NotFound)?;
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| ApiError::Internal)?;
        if !(16..=MAX_PLAINTEXT + 16).contains(&ciphertext.len()) {
            return Err(ApiError::Internal);
        }
        let plaintext = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(id.as_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| ApiError::Internal)?;
        let plaintext = String::from_utf8(plaintext.to_vec()).map_err(|_| ApiError::Internal)?;
        Ok(Record {
            id: id.into(),
            plaintext,
        })
    }
}

fn random_id(rng: &SystemRandom) -> Result<String, ApiError> {
    use std::fmt::Write;
    let mut bytes = [0; 16];
    rng.fill(&mut bytes).map_err(|_| ApiError::Internal)?;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        write!(id, "{byte:02x}").map_err(|_| ApiError::Internal)?;
    }
    Ok(id)
}

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<Store>>,
    token_tag: hmac::Tag,
}

fn token_key() -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, b"aether-local-alpha-bearer-v1")
}

pub fn app(config: &Config) -> Result<Router, &'static str> {
    let state = AppState {
        store: Arc::new(Mutex::new(
            Store::open(&config.db, &config.key).map_err(|_| "database initialization failed")?,
        )),
        token_tag: hmac::sign(&token_key(), config.token.as_bytes()),
    };
    let protected = Router::new()
        .route("/v1/records", post(create_record))
        .route("/v1/records/{id}", get(get_record))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    Ok(Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"status": "ok"})) }),
        )
        .route(
            "/.well-known/palaco-app.json",
            get(|| async {
                Json(serde_json::json!({
                    "id": "aether", "name": "AETHER", "protocol": "palaco-app/v1"
                }))
            }),
        )
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn(no_store))
        .with_state(state))
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn authenticate(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let mut headers = request.headers().get_all(header::AUTHORIZATION).iter();
    let token = headers
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if headers.next().is_some()
        || token.is_none_or(|token| {
            hmac::verify(&token_key(), token.as_bytes(), state.token_tag.as_ref()).is_err()
        })
    {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    next.run(request).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRecord {
    plaintext: String,
}

#[derive(Serialize)]
struct RecordId {
    id: String,
}

#[derive(Serialize)]
struct Record {
    id: String,
    plaintext: String,
}

async fn create_record(
    State(state): State<AppState>,
    body: Result<Json<CreateRecord>, JsonRejection>,
) -> Result<(StatusCode, Json<RecordId>), ApiError> {
    let Json(body) = body.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::TooLarge
        } else {
            ApiError::BadBody
        }
    })?;
    let id = tokio::task::spawn_blocking(move || {
        state
            .store
            .lock()
            .map_err(|_| ApiError::Internal)?
            .insert(&body.plaintext)
    })
    .await
    .map_err(|_| ApiError::Internal)??;
    Ok((StatusCode::CREATED, Json(RecordId { id })))
}

async fn get_record(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Record>, ApiError> {
    tokio::task::spawn_blocking(move || {
        state
            .store
            .lock()
            .map_err(|_| ApiError::Internal)?
            .get(&id)
            .map(Json)
    })
    .await
    .map_err(|_| ApiError::Internal)?
}

#[derive(Debug, PartialEq)]
enum ApiError {
    NotFound,
    TooLarge,
    BadBody,
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::NotFound => (StatusCode::NOT_FOUND, "record not found"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "request too large"),
            Self::BadBody => (StatusCode::BAD_REQUEST, "invalid request body"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "record operation failed"),
        };
        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

#[cfg(test)]
mod tests;
