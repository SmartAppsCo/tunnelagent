use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream as TokioUnixStream;

/// Sent from bash shim binary to the Unix socket server.
#[derive(Debug, Serialize, Deserialize)]
pub struct ShimRequest {
    pub args: Vec<String>,
    pub cwd: String,
}

/// Streamed back from Unix socket server to bash shim binary.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ShimResponse {
    Stdout { data: Vec<u8> },
    Stderr { data: Vec<u8> },
    Done { exit_code: i32 },
}

// --- Synchronous framing (for bash_shim binary) ---

/// Send a length-prefixed message (4-byte big-endian length + payload).
pub fn send_message_sync(stream: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

/// Receive a length-prefixed message.
pub fn recv_message_sync(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// --- Asynchronous framing (for main binary's shim server) ---

/// Send a length-prefixed message asynchronously.
pub async fn send_message_async(stream: &mut TokioUnixStream, data: &[u8]) -> io::Result<()> {
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Receive a length-prefixed message asynchronously.
pub async fn recv_message_async(stream: &mut TokioUnixStream) -> io::Result<Vec<u8>> {
    let len = stream.read_u32().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}
