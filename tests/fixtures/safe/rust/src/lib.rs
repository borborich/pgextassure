//! Lexical noise must not become a finding:
//! `unsafe {}`, `Command::new`, `TcpStream::connect`, and `File::open`.

const SCANNER_NOISE: &str =
    "unsafe std::process::Command std::net::TcpStream std::fs::File";

pub fn add_one(value: i32) -> i32 {
    let _ = SCANNER_NOISE;
    value.saturating_add(1)
}
