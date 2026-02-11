use crate::protocol::{recv_message_sync, send_message_sync, ShimRequest, ShimResponse};
use std::io::{self, Write};
use std::os::unix::net::UnixStream;

/// Entry point when the binary is invoked as "bash" (via argv[0] symlink).
/// Intentionally synchronous — no tokio runtime needed.
pub fn run() -> ! {
    // Check TUNNELAGENT_SOCK env var; if missing, fallback to /usr/bin/bash
    let socket_path = match std::env::var("TUNNELAGENT_SOCK") {
        Ok(p) => p,
        Err(_) => {
            let args: Vec<String> = std::env::args().skip(1).collect();
            let status = std::process::Command::new("/usr/bin/bash")
                .args(&args)
                .status()
                .unwrap_or_else(|_| std::process::exit(127));
            std::process::exit(status.code().unwrap_or(1));
        }
    };

    // Connect to Unix socket
    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "tunnelagent-shim: failed to connect to {}: {}",
                socket_path, e
            );
            std::process::exit(1);
        }
    };

    // Send ShimRequest (args + cwd)
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/".to_string());
    let request = ShimRequest { args, cwd };
    let request_json = serde_json::to_vec(&request).unwrap();
    if let Err(e) = send_message_sync(&mut stream, &request_json) {
        eprintln!("tunnelagent-shim: failed to send request: {}", e);
        std::process::exit(1);
    }

    // Read streaming responses
    loop {
        let data = match recv_message_sync(&mut stream) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("tunnelagent-shim: connection error: {}", e);
                std::process::exit(1);
            }
        };
        let response: ShimResponse = match serde_json::from_slice(&data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("tunnelagent-shim: invalid response: {}", e);
                std::process::exit(1);
            }
        };
        match response {
            ShimResponse::Stdout { data } => {
                let _ = io::stdout().write_all(&data);
                let _ = io::stdout().flush();
            }
            ShimResponse::Stderr { data } => {
                let _ = io::stderr().write_all(&data);
                let _ = io::stderr().flush();
            }
            ShimResponse::Done { exit_code } => {
                std::process::exit(exit_code);
            }
        }
    }
}
