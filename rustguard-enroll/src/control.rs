//! Control socket for the enrollment server.
//!
//! A UNIX domain socket that accepts commands from `rustguard open`.
//! Protocol is dead simple: one line per command.
//!
//!   "OPEN <seconds>\n"  -> opens enrollment for N seconds
//!   "STATUS\n"          -> returns enrollment status + peer count

use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default socket path.
pub fn socket_path() -> PathBuf {
    PathBuf::from("/tmp/rustguard.sock")
}

/// Shared enrollment window state.
/// Stores the UNIX timestamp when enrollment closes. 0 = closed.
pub type EnrollmentWindow = Arc<AtomicI64>;

pub fn new_window() -> EnrollmentWindow {
    Arc::new(AtomicI64::new(0))
}

/// Check if enrollment is currently open.
pub fn is_open(window: &EnrollmentWindow) -> bool {
    let deadline = window.load(Ordering::Relaxed);
    if deadline == 0 {
        return false;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    now < deadline
}

/// Open enrollment for `duration_secs` seconds.
pub fn open_window(window: &EnrollmentWindow, duration_secs: u64) {
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + duration_secs as i64;
    window.store(deadline, Ordering::Relaxed);
}

/// Close enrollment immediately.
pub fn close_window(window: &EnrollmentWindow) {
    window.store(0, Ordering::Relaxed);
}

/// Seconds remaining in the enrollment window. 0 if closed.
pub fn remaining(window: &EnrollmentWindow) -> u64 {
    let deadline = window.load(Ordering::Relaxed);
    if deadline == 0 {
        return 0;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if now >= deadline {
        0
    } else {
        (deadline - now) as u64
    }
}

/// Start the control socket listener in a background thread.
/// Returns the socket path for cleanup.
pub fn start_listener(
    window: EnrollmentWindow,
    peer_count: Arc<std::sync::Mutex<usize>>,
) -> io::Result<PathBuf> {
    let path = socket_path();

    // Remove stale socket.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;
    // Make it world-writable so non-root can send commands
    // (the daemon runs as root, the CLI might not).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    }

    let path_clone = path.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            handle_client(stream, &window, &peer_count);
        }
    });

    Ok(path_clone)
}

fn handle_client(
    stream: std::os::unix::net::UnixStream,
    window: &EnrollmentWindow,
    peer_count: &Arc<std::sync::Mutex<usize>>,
) {
    let reader = io::BufReader::new(&stream);
    let mut writer = &stream;

    for line in reader.lines() {
        let Ok(line) = line else { break };
        let parts: Vec<&str> = line.trim().split_whitespace().collect();

        match parts.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("OPEN") => {
                let secs: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(60);
                open_window(window, secs);
                let msg = format!("OK enrollment open for {secs}s\n");
                let _ = writer.write_all(msg.as_bytes());
            }
            Some("CLOSE") => {
                close_window(window);
                let _ = writer.write_all(b"OK enrollment closed\n");
            }
            Some("STATUS") => {
                let rem = remaining(window);
                let count = *peer_count.lock().unwrap();
                let status = if rem > 0 {
                    format!("OPEN {rem}s remaining, {count} peers\n")
                } else {
                    format!("CLOSED, {count} peers\n")
                };
                let _ = writer.write_all(status.as_bytes());
            }
            _ => {
                let _ = writer.write_all(b"ERR unknown command\n");
            }
        }
    }
}

/// Send a command to the running server via the control socket.
pub fn send_command(cmd: &str) -> io::Result<String> {
    use std::os::unix::net::UnixStream;

    let path = socket_path();
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot connect to rustguard (is the server running?): {e}"),
        )
    })?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    stream.write_all(cmd.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut response = String::new();
    io::BufReader::new(&stream).read_line(&mut response)?;
    Ok(response)
}

/// Cleanup: remove the socket file.
pub fn cleanup(path: &Path) {
    let _ = std::fs::remove_file(path);
}
