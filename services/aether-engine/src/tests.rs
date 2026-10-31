use super::*;
use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_TOKEN: &str = "aether-test-only-bearer-token-0001";

struct Database(PathBuf);

impl Database {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-data");
        fs::create_dir_all(&directory).unwrap();
        Self(directory.join(format!("{}.db", random_id(&SystemRandom::new()).unwrap())))
    }

    fn store(&self, key: &[u8; 32]) -> Store {
        Store::open(&self.0, key).unwrap()
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn config() -> Config {
    Config::parse(Some(TEST_TOKEN.into()), Some("00".repeat(32)), None, None).unwrap()
}

#[test]
fn config_requires_credentials() {
    assert!(Config::parse(None, Some("00".repeat(32)), None, None).is_err());
    assert!(Config::parse(Some(TEST_TOKEN.into()), None, None, None).is_err());
    for token in ["", "short", "with space", "line\nbreak", "nonascii-é"] {
        assert!(Config::parse(Some(token.into()), Some("00".repeat(32)), None, None).is_err());
    }
    for token in [
        "x".repeat(31),
        "x".repeat(4097),
        format!("{} ", "x".repeat(32)),
        format!("{}\t", "x".repeat(32)),
        format!("{}é", "x".repeat(32)),
    ] {
        assert!(Config::parse(Some(token), Some("00".repeat(32)), None, None).is_err());
    }
    for length in [32, 4096] {
        assert!(Config::parse(Some("x".repeat(length)), Some("00".repeat(32)), None, None).is_ok());
    }
}

#[test]
fn config_rejects_bad_keys_and_optional_values() {
    for key in ["".into(), "00".repeat(31), "00".repeat(33), "gg".repeat(32)] {
        assert!(Config::parse(Some(TEST_TOKEN.into()), Some(key), None, None).is_err());
    }
    for port in ["", "0", "65536", "-1", "abc", "127.0.0.1:8787"] {
        assert!(
            Config::parse(
                Some(TEST_TOKEN.into()),
                Some("00".repeat(32)),
                None,
                Some(port.into())
            )
            .is_err()
        );
    }
    assert!(
        Config::parse(
            Some(TEST_TOKEN.into()),
            Some("00".repeat(32)),
            Some(" ".into()),
            None
        )
        .is_err()
    );
}

#[test]
fn config_defaults_and_overrides_are_loopback_only() {
    let default = config();
    assert_eq!(default.address().to_string(), "127.0.0.1:8787");
    assert_eq!(default.db, PathBuf::from("aether.db"));
    let override_config = Config::parse(
        Some(TEST_TOKEN.into()),
        Some("aB".repeat(32)),
        Some("custom.db".into()),
        Some("9876".into()),
    )
    .unwrap();
    assert_eq!(override_config.address().to_string(), "127.0.0.1:9876");
    assert_eq!(override_config.key, [0xab; 32]);
    assert_eq!(override_config.db, PathBuf::from("custom.db"));
}

#[test]
fn roundtrip_and_reopen() {
    let database = Database::new();
    let id = {
        let mut store = database.store(&[1; 32]);
        let id = store.insert("Hello, 世界 🦀").unwrap();
        assert_eq!(store.get(&id).unwrap().plaintext, "Hello, 世界 🦀");
        id
    };
    let store = database.store(&[1; 32]);
    let record = store.get(&id).unwrap();
    assert_eq!(record.id, id);
    assert_eq!(record.plaintext, "Hello, 世界 🦀");
}

#[test]
fn plaintext_and_key_are_absent_at_rest() {
    let database = Database::new();
    let plaintext = "PRIVATE-RECORD-MARKER-that-must-never-be-written-as-plaintext";
    let key = [0x6d; 32];
    {
        let mut store = database.store(&key);
        store.insert(plaintext).unwrap();
        let columns: Vec<String> = store
            .connection
            .prepare("PRAGMA table_info(records)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(columns, ["id", "nonce", "ciphertext"]);
    }
    let bytes = fs::read(&database.0).unwrap();
    assert!(
        !bytes
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_bytes())
    );
    assert!(!bytes.windows(key.len()).any(|w| w == key));
}

#[cfg(unix)]
#[test]
fn database_permissions_are_private_for_new_and_existing_files() {
    use std::os::unix::fs::PermissionsExt;
    let database = Database::new();
    drop(database.store(&[1; 32]));
    assert_eq!(
        fs::metadata(&database.0).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&database.0, fs::Permissions::from_mode(0o666)).unwrap();
    drop(database.store(&[1; 32]));
    assert_eq!(
        fs::metadata(&database.0).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn wrong_key_cannot_decrypt() {
    let database = Database::new();
    let id = database.store(&[1; 32]).insert("private").unwrap();
    assert!(matches!(
        database.store(&[2; 32]).get(&id),
        Err(ApiError::Internal)
    ));
}

#[test]
fn ciphertext_tampering_is_rejected() {
    let database = Database::new();
    let mut store = database.store(&[1; 32]);
    let id = store.insert("private").unwrap();
    store
        .connection
        .execute(
            "UPDATE records SET ciphertext = zeroblob(length(ciphertext)) WHERE id = ?1",
            params![id],
        )
        .unwrap();
    assert!(matches!(store.get(&id), Err(ApiError::Internal)));
}

#[test]
fn nonce_tampering_and_malformed_nonce_are_rejected() {
    let database = Database::new();
    let mut store = database.store(&[1; 32]);
    let id = store.insert("private").unwrap();
    let mut nonce: Vec<u8> = store
        .connection
        .query_row("SELECT nonce FROM records WHERE id = ?1", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    nonce[0] ^= 1;
    store
        .connection
        .execute(
            "UPDATE records SET nonce = ?1 WHERE id = ?2",
            params![nonce, id],
        )
        .unwrap();
    assert!(matches!(store.get(&id), Err(ApiError::Internal)));
    store
        .connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    store
        .connection
        .execute("UPDATE records SET nonce = x'01' WHERE id = ?1", [&id])
        .unwrap();
    assert!(matches!(store.get(&id), Err(ApiError::Internal)));
}

#[test]
fn id_is_bound_by_authenticated_data() {
    let database = Database::new();
    let mut store = database.store(&[1; 32]);
    let id = store.insert("private").unwrap();
    let replacement = random_id(&SystemRandom::new()).unwrap();
    store
        .connection
        .execute(
            "UPDATE records SET id = ?1 WHERE id = ?2",
            params![replacement, id],
        )
        .unwrap();
    assert!(matches!(store.get(&replacement), Err(ApiError::Internal)));
}

#[test]
fn nonces_are_random_unique_and_database_enforces_uniqueness() {
    let database = Database::new();
    let mut store = database.store(&[1; 32]);
    for _ in 0..64 {
        store.insert("same plaintext").unwrap();
    }
    let (count, unique): (u32, u32) = store
        .connection
        .query_row(
            "SELECT count(*), count(DISTINCT nonce) FROM records",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((count, unique), (64, 64));
    assert!(
        store
            .connection
            .execute(
                "INSERT INTO records SELECT ?1, nonce, ciphertext FROM records LIMIT 1",
                [random_id(&SystemRandom::new()).unwrap()]
            )
            .is_err()
    );
}

#[test]
fn storage_bounds_empty_and_missing_records() {
    let database = Database::new();
    let mut store = database.store(&[1; 32]);
    let empty = store.insert("").unwrap();
    assert_eq!(store.get(&empty).unwrap().plaintext, "");
    let boundary = store.insert(&"a".repeat(MAX_PLAINTEXT)).unwrap();
    assert_eq!(store.get(&boundary).unwrap().plaintext.len(), MAX_PLAINTEXT);
    assert_eq!(
        store.insert(&"a".repeat(MAX_PLAINTEXT + 1)),
        Err(ApiError::TooLarge)
    );
    for id in ["0".repeat(32), "' OR 1=1 --".into(), "".into()] {
        assert!(matches!(store.get(&id), Err(ApiError::NotFound)));
    }
}

struct Server {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    _database: Database,
}

impl Server {
    async fn start() -> Self {
        let database = Database::new();
        let mut config = config();
        config.db = database.0.clone();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let router = app(&config).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            address,
            task,
            _database: database,
        }
    }

    async fn request(&self, method: &str, path: &str, headers: &str, body: &str) -> (u16, String) {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, response)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

const AUTH: &str = concat!(
    "Authorization: ",
    "Bearer ",
    "aether-test-only-bearer-token-0001",
    "\r\n"
);
const AUTH_JSON: &str = concat!(
    "Authorization: ",
    "Bearer ",
    "aether-test-only-bearer-token-0001",
    "\r\nContent-Type: application/json\r\n"
);

fn json_body(response: &str) -> serde_json::Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}

#[tokio::test]
async fn http_public_manifest_and_health() {
    let server = Server::start().await;
    for path in ["/health", "/.well-known/palaco-app.json"] {
        let (status, response) = server.request("GET", path, "", "").await;
        assert_eq!(status, 200);
        assert!(response.contains("cache-control: no-store"));
        assert!(!response.contains("access-control-allow-origin"));
        if path != "/health" {
            assert_eq!(
                json_body(&response),
                serde_json::json!({"id":"aether","name":"AETHER","protocol":"palaco-app/v1"})
            );
        }
    }
}

#[tokio::test]
async fn http_roundtrip_and_not_found() {
    let server = Server::start().await;
    let (status, response) = server
        .request(
            "POST",
            "/v1/records",
            AUTH_JSON,
            r#"{"plaintext":"hello 🦀"}"#,
        )
        .await;
    assert_eq!(status, 201);
    let id = json_body(&response)["id"].as_str().unwrap().to_owned();
    let (status, response) = server
        .request("GET", &format!("/v1/records/{id}"), AUTH_JSON, "")
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        json_body(&response),
        serde_json::json!({"id":id,"plaintext":"hello 🦀"})
    );
    for id in ["0".repeat(32), "invalid-id".into()] {
        let (status, _) = server
            .request("GET", &format!("/v1/records/{id}"), AUTH_JSON, "")
            .await;
        assert_eq!(status, 404);
    }
}

#[tokio::test]
async fn http_auth_rejects_missing_wrong_and_duplicate_tokens() {
    let server = Server::start().await;
    for headers in [
        "",
        concat!("Authorization: ", "Bearer ", "wrong", "\r\n"),
        "Authorization: Basic test-only-bearer\r\n",
        concat!("Authorization: ", "Bearer ", "\r\n"),
        concat!(
            "Authorization: ",
            "Bearer ",
            "aether-test-only-bearer-token-0001",
            "\r\n",
            "Authorization: ",
            "Bearer ",
            "aether-test-only-bearer-token-0001",
            "\r\n"
        ),
    ] {
        for (method, path) in [("POST", "/v1/records"), ("GET", "/v1/records/unknown")] {
            let (status, response) = server.request(method, path, headers, "not json").await;
            assert_eq!(status, 401);
            assert!(response.contains("www-authenticate: Bearer"));
            assert_eq!(
                json_body(&response),
                serde_json::json!({"error":"unauthorized"})
            );
        }
    }
}

#[tokio::test]
async fn http_malformed_json_and_plaintext_limits() {
    let server = Server::start().await;
    for body in [
        "{",
        "{}",
        r#"{"plaintext":1}"#,
        r#"{"plaintext":"x","extra":true}"#,
    ] {
        let (status, response) = server.request("POST", "/v1/records", AUTH_JSON, body).await;
        assert_eq!(status, 400);
        assert_eq!(
            json_body(&response),
            serde_json::json!({"error":"invalid request body"})
        );
    }
    let (status, _) = server.request("POST", "/v1/records", AUTH, "{}").await;
    assert_eq!(status, 400);
    for (length, expected) in [
        (MAX_PLAINTEXT, 201),
        (MAX_PLAINTEXT + 1, 413),
        (MAX_BODY, 413),
    ] {
        let body = serde_json::json!({"plaintext":"x".repeat(length)}).to_string();
        let (status, _) = server
            .request("POST", "/v1/records", AUTH_JSON, &body)
            .await;
        assert_eq!(status, expected);
    }
    let body = serde_json::json!({"plaintext":"é".repeat(MAX_PLAINTEXT / 2 + 1)}).to_string();
    assert_eq!(
        server
            .request("POST", "/v1/records", AUTH_JSON, &body)
            .await
            .0,
        413
    );
}

#[tokio::test]
async fn http_chunked_body_limit() {
    let server = Server::start().await;
    let mut stream = tokio::net::TcpStream::connect(server.address)
        .await
        .unwrap();
    let chunk = "x".repeat(MAX_BODY + 1);
    let request = format!(
        "POST /v1/records HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n{AUTH_JSON}\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
        chunk.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 413")
    );
}

#[tokio::test]
async fn http_storage_errors_are_generic() {
    let server = Server::start().await;
    let mut store = server._database.store(&[0; 32]);
    let id = store.insert("private").unwrap();
    store
        .connection
        .execute(
            "UPDATE records SET ciphertext = zeroblob(16) WHERE id = ?1",
            [&id],
        )
        .unwrap();
    let (status, response) = server
        .request("GET", &format!("/v1/records/{id}"), AUTH_JSON, "")
        .await;
    assert_eq!(status, 500);
    assert_eq!(
        json_body(&response),
        serde_json::json!({"error":"record operation failed"})
    );
    assert!(!response.contains("SQLite"));
    assert!(!response.contains("private"));
}
