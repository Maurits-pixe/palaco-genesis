use aether_engine::{Config, app};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("AETHER: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), &'static str> {
    let config = Config::from_env()?;
    let app = app(&config)?;
    let listener = tokio::net::TcpListener::bind(config.address())
        .await
        .map_err(|_| "could not bind loopback listener")?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "could not install shutdown handler")?;
    let shutdown = async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|_| "HTTP server stopped unexpectedly")
}
