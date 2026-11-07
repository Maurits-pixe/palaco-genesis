#![cfg(unix)]

use ring::rand::{SecureRandom, SystemRandom};
use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aether-engine"));
    for name in ["AETHER_TOKEN", "AETHER_KEY_HEX", "AETHER_DB", "AETHER_PORT"] {
        command.env_remove(name);
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    command
}

fn random_hex() -> String {
    let mut bytes = [0; 32];
    SystemRandom::new().fill(&mut bytes).unwrap();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Database(PathBuf);

impl Drop for Database {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "process did not exit promptly");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn binary_rejects_missing_or_bad_configuration() {
    for (token, key, port) in [
        (None, None, None),
        (Some("short".into()), Some(random_hex()), None),
        (Some(random_hex()), Some("bad".into()), None),
        (Some(random_hex()), Some(random_hex()), Some("0")),
    ] {
        let mut command = command();
        if let Some(token) = token {
            command.env("AETHER_TOKEN", token);
        }
        if let Some(key) = key {
            command.env("AETHER_KEY_HEX", key);
        }
        if let Some(port) = port {
            command.env("AETHER_PORT", port);
        }
        let mut process = Process(command.spawn().unwrap());
        assert!(!wait_for_exit(&mut process.0).success());
    }
}

fn request(address: SocketAddr, token: &str, method: &str, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let scheme = "Bearer";
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: {scheme} {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn binary_sigterm_is_graceful_and_records_survive_restart() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-data");
    fs::create_dir_all(&directory).unwrap();
    let database = Database(directory.join(format!("{}.db", random_hex())));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let token = random_hex();
    let key = random_hex();
    let mut id = String::new();
    for restart in 0..2 {
        let mut process = Process(
            command()
                .env("AETHER_TOKEN", &token)
                .env("AETHER_KEY_HEX", &key)
                .env("AETHER_DB", &database.0)
                .env("AETHER_PORT", address.port().to_string())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(process.0.try_wait().unwrap().is_none(), "startup failed");
            if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "listener did not become responsive"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(request(address, &token, "GET", "/health", "").starts_with("HTTP/1.1 200"));
        if restart == 0 {
            let response = request(
                address,
                &token,
                "POST",
                "/v1/records",
                r#"{"plaintext":"persistent across graceful restart"}"#,
            );
            assert!(response.starts_with("HTTP/1.1 201"));
            let body: serde_json::Value =
                serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
            id = body["id"].as_str().unwrap().into();
        }
        let response = request(address, &token, "GET", &format!("/v1/records/{id}"), "");
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("persistent across graceful restart"));
        assert!(
            Command::new("kill")
                .arg("-TERM")
                .arg(process.0.id().to_string())
                .status()
                .unwrap()
                .success()
        );
        assert!(wait_for_exit(&mut process.0).success());
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
    }
}
