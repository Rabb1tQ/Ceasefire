//! Pipe availability probe: open the pipe N times with a gap, report each.
//! Usage: pipe-hammer.exe [count] [gap_ms]
use std::io::{Read, Write};

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let gap: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(500);
    let pipe = r"\\.\pipe\CeasefireFirewall";
    for i in 0..n {
        let t = std::time::Instant::now();
        match std::fs::OpenOptions::new().read(true).write(true).open(pipe) {
            Ok(mut f) => {
                use ceasefire_service::models::{IpcRequest, IpcResponse};
                use std::io::Read;
                let req = bincode::serialize(&IpcRequest::ListRules { offset: 0, limit: u32::MAX, search: None }).unwrap();
                if let Err(e) = f.write_all(&(req.len() as u32).to_le_bytes()) { println!("[{:02}] WLEN FAIL {}", i, e); continue; }
                if let Err(e) = f.write_all(&req) { println!("[{:02}] WBODY FAIL {}", i, e); continue; }
                let mut lb = [0u8;4];
                match f.read_exact(&mut lb) {
                    Ok(_) => {
                        let mut body = vec![0u8; u32::from_le_bytes(lb) as usize];
                        match f.read_exact(&mut body) {
                            Ok(_) => println!("[{:02}] REQ OK ({:?})", i, t.elapsed()),
                            Err(e) => println!("[{:02}] RBODY FAIL {}", i, e),
                        }
                    }
                    Err(e) => println!("[{:02}] RLEN FAIL: {} ({:?})", i, e, t.elapsed()),
                }
            }
            Err(e) => println!("[{:02}] open FAIL: {} ({:?})", i, e, t.elapsed()),
        }
        std::thread::sleep(std::time::Duration::from_millis(gap));
    }
}
