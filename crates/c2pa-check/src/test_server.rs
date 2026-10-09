pub struct Request {
    pub path: String,
    pub authorization: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

fn read_request(stream: &mut std::net::TcpStream) -> Request {
    use std::io::Read;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "the client closed before sending headers");
        raw.extend_from_slice(&chunk[..n]);
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let header = |name: &str| {
        head.lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_string())
            })
            .unwrap_or_default()
    };
    let length: usize = header("content-length").parse().unwrap_or(0);
    while raw.len() < head_end + length {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "the client closed mid-body");
        raw.extend_from_slice(&chunk[..n]);
    }

    Request {
        path: head
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_string(),
        content_type: header("content-type"),
        authorization: header("authorization"),
        body: raw[head_end..head_end + length].to_vec(),
    }
}

pub fn serve(
    requests: usize,
    handler: impl Fn(&Request) -> (u16, String) + Send + 'static,
) -> (String, std::thread::JoinHandle<Vec<String>>) {
    use std::io::Write;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut paths = Vec::new();
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let (status, body) = handler(&request);
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            ;
            paths.push(request.path);
        }
        paths
    });
    (base, handle)
}
