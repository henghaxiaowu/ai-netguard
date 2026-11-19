use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const PAC_PORT: u16 = 17898;

pub struct PacServer {
    started: AtomicBool,
    browser_port: Arc<AtomicU16>,
}

impl PacServer {
    pub fn new(initial_browser_port: u16) -> Self {
        Self {
            started: AtomicBool::new(false),
            browser_port: Arc::new(AtomicU16::new(initial_browser_port)),
        }
    }

    pub fn ensure_started(&self, browser_port: u16) -> Result<(), String> {
        let _ = self.ensure_started_on(PAC_PORT, browser_port)?;
        Ok(())
    }

    fn ensure_started_on(&self, listen_port: u16, browser_port: u16) -> Result<u16, String> {
        self.browser_port.store(browser_port, Ordering::SeqCst);
        if self.started.load(Ordering::SeqCst) {
            return Ok(listen_port);
        }

        let listener = TcpListener::bind(("127.0.0.1", listen_port))
            .map_err(|e| format!("启动本地 PAC 服务 (127.0.0.1:{listen_port}) 失败: {e}"))?;
        let bound_port = listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(listen_port);
        let port_ref = self.browser_port.clone();
        self.started.store(true, Ordering::SeqCst);

        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let port_ref = port_ref.clone();
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                    let mut buf = [0u8; 4096];
                    let mut total_read = 0usize;
                    while total_read < buf.len() {
                        match stream.read(&mut buf[total_read..]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                total_read += n;
                                if buf[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let socks_port = port_ref.load(Ordering::SeqCst);
                    let pac_body = format!(
                        "function FindProxyForURL(url, host) {{ if (isPlainHostName(host) || host === \"localhost\" || host === \"127.0.0.1\" || host === \"::1\") return \"DIRECT\"; return \"SOCKS5 127.0.0.1:{socks_port}\"; }}\n"
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                        pac_body.len(),
                        pac_body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                });
            }
        });
        Ok(bound_port)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    #[test]
    fn pac_server_serves_socks5_config() {
        let srv = PacServer::new(17891);
        let port = srv
            .ensure_started_on(PAC_PORT, 17891)
            .or_else(|_| srv.ensure_started_on(0, 17891))
            .unwrap();
        let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
        conn.write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        conn.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("DIRECT"));
        assert!(resp.contains("SOCKS5 127.0.0.1:17891"));
    }
}
