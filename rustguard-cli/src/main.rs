use std::path::PathBuf;
use std::process;

use rustguard_daemon::config::Config;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("up") => cmd_up(&args[2..]),
        Some("serve") => cmd_serve(&args[2..]),
        Some("join") => cmd_join(&args[2..]),
        Some("open") => cmd_open(&args[2..]),
        Some("close") => cmd_close(),
        Some("status") => cmd_status(),
        Some("genkey") => cmd_genkey(),
        Some("pubkey") => cmd_pubkey(),
        Some(cmd) => {
            eprintln!("unknown command: {cmd}");
            usage();
            process::exit(1);
        }
        None => {
            usage();
            process::exit(1);
        }
    }
}

fn usage() {
    eprintln!("usage: rustguard <command>");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  up <config>                          bring up a WireGuard tunnel (standard mode)");
    eprintln!("  serve --pool <cidr> --token <token>   start enrollment server");
    eprintln!("  join <endpoint> --token <token>       join a server (zero-config mode)");
    eprintln!("  open [seconds]                        open enrollment window (default 60s)");
    eprintln!("  close                                 close enrollment window");
    eprintln!("  status                                show server status");
    eprintln!("  genkey                                generate a private key");
    eprintln!("  pubkey                                derive public key from stdin");
}

fn cmd_up(args: &[String]) {
    let config_path = match args.first() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: rustguard up <config>");
            process::exit(1);
        }
    };

    let config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read config: {e}");
            process::exit(1);
        }
    };

    println!("rustguard starting...");
    if let Err(e) = rustguard_daemon::tunnel::run(config) {
        eprintln!("tunnel error: {e}");
        process::exit(1);
    }
}

fn cmd_serve(args: &[String]) {
    let mut pool = None;
    let mut token = None;
    let mut port = 51820u16;
    let mut open_immediately = false;
    let mut xdp_ifname = None;
    let mut tun_queues = 1usize;
    let mut use_uring = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--pool" => {
                i += 1;
                pool = Some(args.get(i).cloned().unwrap_or_default());
            }
            "--token" => {
                i += 1;
                token = Some(args.get(i).cloned().unwrap_or_default());
            }
            "--open" => {
                open_immediately = true;
            }
            "--xdp" => {
                i += 1;
                xdp_ifname = Some(args.get(i).cloned().unwrap_or_default());
            }
            "--queues" => {
                i += 1;
                tun_queues = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--uring" => {
                use_uring = true;
            }
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(51820);
            }
            _ => {
                eprintln!("unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let pool_str = pool.unwrap_or_else(|| {
        eprintln!("usage: rustguard serve --pool <cidr> --token <token>");
        process::exit(1);
    });
    let token = token.unwrap_or_else(|| {
        eprintln!("usage: rustguard serve --pool <cidr> --token <token>");
        process::exit(1);
    });

    let (net_str, prefix_str) = pool_str.split_once('/').unwrap_or((&pool_str, "24"));
    let network: std::net::Ipv4Addr = net_str.parse().unwrap_or_else(|e| {
        eprintln!("bad pool address: {e}");
        process::exit(1);
    });
    let prefix: u8 = prefix_str.parse().unwrap_or_else(|e| {
        eprintln!("bad pool prefix: {e}");
        process::exit(1);
    });

    let config = rustguard_enroll::server::ServeConfig {
        listen_port: port,
        pool_network: network,
        pool_prefix: prefix,
        token,
        open_immediately,
        state_path: Some(rustguard_enroll::state::default_state_path()),
        xdp_ifname,
        tun_queues,
        use_uring,
    };

    if let Err(e) = rustguard_enroll::server::run(config) {
        eprintln!("serve error: {e}");
        process::exit(1);
    }
}

fn cmd_join(args: &[String]) {
    let mut endpoint = None;
    let mut token = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--token" => {
                i += 1;
                token = Some(args.get(i).cloned().unwrap_or_default());
            }
            s if !s.starts_with('-') && endpoint.is_none() => {
                endpoint = Some(s.to_string());
            }
            _ => {
                eprintln!("unknown option: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let endpoint_str = endpoint.unwrap_or_else(|| {
        eprintln!("usage: rustguard join <endpoint> --token <token>");
        process::exit(1);
    });
    let token = token.unwrap_or_else(|| {
        eprintln!("usage: rustguard join <endpoint> --token <token>");
        process::exit(1);
    });

    let server_endpoint: std::net::SocketAddr = endpoint_str.parse().unwrap_or_else(|e| {
        eprintln!("bad endpoint: {e}");
        process::exit(1);
    });

    let config = rustguard_enroll::client::JoinConfig {
        server_endpoint,
        token,
    };

    if let Err(e) = rustguard_enroll::client::run(config) {
        eprintln!("join error: {e}");
        process::exit(1);
    }
}

fn cmd_open(args: &[String]) {
    let secs: u64 = args
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    match rustguard_enroll::control::send_command(&format!("OPEN {secs}")) {
        Ok(resp) => print!("{resp}"),
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    }
}

fn cmd_close() {
    match rustguard_enroll::control::send_command("CLOSE") {
        Ok(resp) => print!("{resp}"),
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    }
}

fn cmd_status() {
    match rustguard_enroll::control::send_command("STATUS") {
        Ok(resp) => print!("{resp}"),
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    }
}

fn cmd_genkey() {
    use base64::prelude::*;
    let secret = rustguard_crypto::StaticSecret::random();
    println!("{}", BASE64_STANDARD.encode(secret.to_bytes()));
}

fn cmd_pubkey() {
    use base64::prelude::*;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("failed to read stdin");
    let bytes = BASE64_STANDARD
        .decode(input.trim())
        .expect("invalid base64");
    let key: [u8; 32] = bytes.try_into().expect("key must be 32 bytes");
    let secret = rustguard_crypto::StaticSecret::from_bytes(key);
    let public = secret.public_key();
    println!("{}", BASE64_STANDARD.encode(public.as_bytes()));
}
