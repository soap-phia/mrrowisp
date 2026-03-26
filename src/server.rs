use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::{ Bytes, BytesMut };
use futures::stream::{ SplitSink, SplitStream };
use futures::{ SinkExt, StreamExt };
use httparse::Request as HttpRequest;
use portable_pty::CommandBuilder;
use tokio::io::{ AsyncReadExt, AsyncWriteExt };
use tokio::net::{ TcpListener, TcpStream, UdpSocket };
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{ Mutex, mpsc };
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::server::{ Request, Response };
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{ error, info, warn };

use crate::protocol::{ MAXMSG, Packet, StreamType, encode_extensions };
use libc::c_int;
use socket2::SockRef;
use std::os::fd::AsRawFd;

const BYTESMAX: usize = 3 * 1024 * 1024;
const BYTESMID: usize = 1536 * 1024;
const BYTESMIN: usize = 960 * 1024;
const MAXPKTS: usize = 896;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub root: String,
    pub buffer_bytes: u32,
    pub continue_threshold_bytes: u32,
}

pub async fn run(cfg: ServerConfig) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(?addr, "listening for websocket connections");

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, cfg).await {
                warn!(?peer, error = ?e, "connection failed");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    cfg: ServerConfig
) -> anyhow::Result<()> {
    let _ = stream.set_nodelay(true);
    {
        let sock_ref = SockRef::from(&stream);
        let _ = sock_ref.set_recv_buffer_size(16 * 1024 * 1024);
        let _ = sock_ref.set_send_buffer_size(16 * 1024 * 1024);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let raw_fd = stream.as_raw_fd();
        unsafe {
            let one: c_int = 1;
            let _ = libc::setsockopt(
                raw_fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &one as *const c_int as *const _,
                std::mem::size_of::<c_int>() as libc::socklen_t
            );
        }
    }

    let mut has_wisp_proto = false;
    let mut ws_protocol_requested = false;
    let mut peek_buf = [0u8; 1024];
    let n = match
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            stream.peek(&mut peek_buf)
        ).await
    {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    if n > 0 {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = HttpRequest::new(&mut headers);
        if let Ok(res) = req.parse(&peek_buf[..n]) {
            if res.is_complete() {
                let upgrade = req.headers.iter().any(|h| h.name.eq_ignore_ascii_case("upgrade"));
                if !upgrade {
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                    let _ = stream.write_all(response).await;
                    let _ = stream.shutdown().await;
                    return Ok(());
                }
            }
        }
    }

    let ws_stream = tokio_tungstenite::accept_hdr_async(
        stream,
        |req: &Request, mut resp: Response| {
            if let Some(val) = req.headers().get("Sec-WebSocket-Protocol") {
                ws_protocol_requested = true;
                let val_str = val.to_str().unwrap_or_default().to_ascii_lowercase();
                has_wisp_proto = val_str.contains("wisp");
                resp.headers_mut().insert("Sec-WebSocket-Protocol", "wisp".parse().unwrap());
            }
            Ok(resp)
        }
    ).await?;

    info!(?peer, has_wisp_proto, "ws accepted");

    serve_ws(ws_stream, cfg, has_wisp_proto).await
}

async fn serve_ws(
    stream: WebSocketStream<TcpStream>,
    cfg: ServerConfig,
    has_wisp_proto: bool
) -> anyhow::Result<()> {
    let (sink, source) = stream.split();

    let mut initial = Vec::new();
    if has_wisp_proto {
        let extensions = encode_extensions(
            &[
                crate::protocol::Extension::new(0x01, Bytes::new()),
                crate::protocol::Extension::new(0xf0, Bytes::new()),
            ]
        );
        initial.push(Packet::Info {
            stream_id: 0,
            major: 2,
            minor: 0,
            extensions,
        });
    }
    initial.push(Packet::Continue {
        stream_id: 0,
        remaining: cfg.buffer_bytes,
    });

    serve_split_ws(sink, source, cfg, initial).await
}

async fn serve_split_ws(
    mut sink: SplitSink<WebSocketStream<TcpStream>, Message>,
    mut source: SplitStream<WebSocketStream<TcpStream>>,
    cfg: ServerConfig,
    initial: Vec<Packet>
) -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::channel::<Packet>(2048);
    let mut tasks: HashMap<u32, StreamHandle> = HashMap::new();
    let mut last_stream_id: u32 = 0;
    let mut last_stream_handle: Option<mpsc::Sender<StreamCmd>> = None;

    for pkt in initial {
        let mut out = BytesMut::new();
        pkt.encode(&mut out);
        sink.send(Message::Binary(out.freeze().to_vec())).await?;
    }

    let sink_task = {
        let mut sink = sink;
        tokio::spawn(async move {
            let mut out_buf: Vec<u8> = Vec::with_capacity(BYTESMAX * 2);

            loop {
                match rx.recv().await {
                    None => {
                        break;
                    }
                    Some(first) => {
                        out_buf.clear();
                        first.encode_into(&mut out_buf);

                        let mut batched = 1usize;
                        let queue_len = rx.len();
                        let batch_bytes = if queue_len > 192 {
                            BYTESMIN
                        } else if queue_len > 80 {
                            BYTESMID
                        } else {
                            BYTESMAX
                        };

                        while out_buf.len() < batch_bytes && batched < MAXPKTS {
                            match rx.try_recv() {
                                Ok(pkt) => {
                                    pkt.encode_into(&mut out_buf);
                                    batched += 1;
                                }
                                Err(TryRecvError::Empty) => {
                                    break;
                                }
                                Err(TryRecvError::Disconnected) => {
                                    break;
                                }
                            }
                        }

                        let target_cap = batch_bytes * 2;
                        let cap = out_buf.capacity().max(target_cap);
                        let send_buf = std::mem::replace(&mut out_buf, Vec::with_capacity(cap));

                        if let Err(e) = sink.send(Message::Binary(send_buf)).await {
                            error!(error = ?e, "sink send failed");
                            break;
                        }
                    }
                }
            }
        })
    };

    while let Some(msg) = source.next().await {
        let msg = msg?;
        match msg {
            Message::Binary(data) => {
                if data.len() > MAXMSG {
                    warn!(len = data.len(), "drop oversized");
                    continue;
                }
                if let Some(pkt) = Packet::decode_from(&data)? {
                    handle_packet(
                        pkt,
                        &tx,
                        &mut tasks,
                        &cfg,
                        &mut last_stream_id,
                        &mut last_stream_handle
                    ).await?;
                }
            }
            Message::Close(_) => {
                break;
            }
            _ => {}
        }
    }

    sink_task.abort();
    Ok(())
}

async fn handle_packet(
    pkt: Packet,
    tx: &mpsc::Sender<Packet>,
    tasks: &mut HashMap<u32, StreamHandle>,
    cfg: &ServerConfig,
    last_stream_id: &mut u32,
    last_stream_handle: &mut Option<mpsc::Sender<StreamCmd>>
) -> anyhow::Result<()> {
    match pkt {
        Packet::Connect { stream_id, stream_type, port, host } => {
            if tasks.contains_key(&stream_id) {
                return Ok(());
            }
            let tx_to_client = tx.clone();
            let cfg = cfg.clone();
            let (ctrl_tx, ctrl_rx) = mpsc::channel::<StreamCmd>(256);
            match stream_type {
                StreamType::Tcp => {
                    tokio::spawn(
                        handle_tcp(
                            stream_id,
                            host,
                            port,
                            tx_to_client,
                            cfg.buffer_bytes,
                            cfg.continue_threshold_bytes,
                            ctrl_rx
                        )
                    );
                }
                StreamType::Udp => {
                    tokio::spawn(
                        handle_udp(
                            stream_id,
                            host,
                            port,
                            tx_to_client,
                            cfg.buffer_bytes,
                            cfg.continue_threshold_bytes,
                            ctrl_rx
                        )
                    );
                }
                StreamType::Twisp => {
                    tokio::spawn(
                        handle_twisp(
                            stream_id,
                            host,
                            tx_to_client,
                            cfg.root.clone(),
                            cfg.buffer_bytes,
                            cfg.continue_threshold_bytes,
                            ctrl_rx
                        )
                    );
                }
            }
            *last_stream_id = stream_id;
            *last_stream_handle = Some(ctrl_tx.clone());
            tasks.insert(stream_id, StreamHandle { tx: ctrl_tx });
        }
        Packet::Data { stream_id, payload } => {
            if *last_stream_id == stream_id {
                if let Some(handle) = last_stream_handle {
                    let _ = handle.send(StreamCmd::Data(payload)).await;
                    return Ok(());
                }
            }
            if let Some(handle) = tasks.get(&stream_id) {
                *last_stream_id = stream_id;
                *last_stream_handle = Some(handle.tx.clone());
                let _ = handle.tx.send(StreamCmd::Data(payload)).await;
            }
        }
        Packet::TwispResize { stream_id, rows, cols } => {
            if let Some(handle) = tasks.get(&stream_id) {
                let _ = handle.tx.send(StreamCmd::Resize(rows, cols)).await;
            }
        }
        Packet::Close { stream_id, .. } => {
            if *last_stream_id == stream_id {
                *last_stream_id = 0;
                *last_stream_handle = None;
            }
            if let Some(handle) = tasks.remove(&stream_id) {
                let _ = handle.tx.send(StreamCmd::Close(0x02)).await;
            }
        }
        Packet::Continue { .. } | Packet::Info { .. } => {}
    }
    Ok(())
}

#[derive(Clone)]
struct StreamHandle {
    tx: mpsc::Sender<StreamCmd>,
}

#[derive(Debug)]
enum StreamCmd {
    Data(Bytes),
    Close(u8),
    Resize(u16, u16),
}

async fn handle_tcp(
    stream_id: u32,
    host: String,
    port: u16,
    tx: mpsc::Sender<Packet>,
    buffer_bytes: u32,
    continue_threshold_bytes: u32,
    mut rx: mpsc::Receiver<StreamCmd>
) {
    let addr = format!("{host}:{port}");
    match TcpStream::connect(addr.clone()).await {
        Ok(socket) => {
            let _ = socket.set_nodelay(true);
            let raw_fd = socket.as_raw_fd();
            let sock_ref = SockRef::from(&socket);
            let _ = sock_ref.set_recv_buffer_size(16 * 1024 * 1024);
            let _ = sock_ref.set_send_buffer_size(16 * 1024 * 1024);
            #[cfg(target_os = "linux")]
            unsafe {
                let one: c_int = 1;
                let _ = libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_QUICKACK,
                    &one as *const c_int as *const _,
                    std::mem::size_of::<c_int>() as libc::socklen_t
                );
            }
            let _ = tx.send(Packet::Continue {
                stream_id,
                remaining: buffer_bytes,
            }).await;

            let (reader, writer) = socket.into_split();
            let mut reader = tokio::io::BufReader::with_capacity(256 * 1024, reader);

            let read_tx = tx.clone();
            tokio::spawn(async move {
                let mut buf1 = vec![0u8; 131072];
                let mut buf2 = vec![0u8; 131072];
                let mut use_first = true;
                loop {
                    let buf = if use_first { &mut buf1 } else { &mut buf2 };
                    match reader.read(buf).await {
                        Ok(0) => {
                            let _ = read_tx.send(Packet::Close {
                                stream_id,
                                reason: 0x02,
                            }).await;
                            break;
                        }
                        Ok(n) => {
                            let payload = Bytes::copy_from_slice(&buf[..n]);
                            let _ = read_tx.send(Packet::Data { stream_id, payload }).await;
                            use_first = !use_first;
                        }
                        Err(e) => {
                            warn!(?e, stream_id, "tcp read error");
                            let _ = read_tx.send(Packet::Close {
                                stream_id,
                                reason: 0x03,
                            }).await;
                            break;
                        }
                    }
                }
            });

            let mut sent_since_continue = 0u32;
            let mut sent_bytes_since_continue = 0u32;
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    StreamCmd::Data(payload) => {
                        #[cfg(target_os = "linux")]
                        {
                            use std::os::unix::io::AsRawFd;
                            let fd = writer.as_ref().as_raw_fd();
                            let res = unsafe {
                                libc::send(
                                    fd,
                                    payload.as_ptr() as *const libc::c_void,
                                    payload.len(),
                                    libc::MSG_NOSIGNAL
                                )
                            };
                            if res == -1 {
                                warn!(error = ?std::io::Error::last_os_error(), stream_id, "tcp write error (send)");
                                let _ = tx.send(Packet::Close {
                                    stream_id,
                                    reason: 0x03,
                                }).await;
                                break;
                            }
                        }
                        sent_since_continue = sent_since_continue.saturating_add(1);
                        sent_bytes_since_continue = sent_bytes_since_continue.saturating_add(
                            payload.len() as u32
                        );
                        if sent_bytes_since_continue >= continue_threshold_bytes {
                            let _ = tx.send(Packet::Continue {
                                stream_id,
                                remaining: buffer_bytes,
                            }).await;
                            sent_since_continue = 0;
                            sent_bytes_since_continue = 0;
                        }
                    }
                    StreamCmd::Close(reason) => {
                        let _ = tx.send(Packet::Close { stream_id, reason }).await;
                        break;
                    }
                    StreamCmd::Resize(_, _) => {}
                }
            }
        }
        Err(e) => {
            warn!(?e, stream_id, "tcp connect failed");
            let _ = tx.send(Packet::Close {
                stream_id,
                reason: 0x44,
            });
        }
    }
}

async fn handle_udp(
    stream_id: u32,
    host: String,
    port: u16,
    tx: mpsc::Sender<Packet>,
    buffer_bytes: u32,
    continue_threshold_bytes: u32,
    mut rx: mpsc::Receiver<StreamCmd>
) {
    let addr = format!("{host}:{port}");
    match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            if let Err(e) = socket.connect(addr.clone()).await {
                warn!(?e, stream_id, "udp connect failed");
                let _ = tx.send(Packet::Close {
                    stream_id,
                    reason: 0x44,
                }).await;
                return;
            }
            let socket = Arc::new(socket);
            let _raw_fd = socket.as_raw_fd();
            let sock_ref = SockRef::from(&socket);
            let _ = sock_ref.set_recv_buffer_size(16 * 1024 * 1024);
            let _ = sock_ref.set_send_buffer_size(16 * 1024 * 1024);
            let _ = tx.send(Packet::Continue {
                stream_id,
                remaining: buffer_bytes,
            }).await;

            let read_tx = tx.clone();
            let read_socket = socket.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    match read_socket.recv(&mut buf).await {
                        Ok(0) => {}
                        Ok(n) => {
                            let payload = Bytes::copy_from_slice(&buf[..n]);
                            let _ = read_tx.send(Packet::Data { stream_id, payload }).await;
                        }
                        Err(e) => {
                            warn!(?e, stream_id, "udp read error");
                            let _ = read_tx.send(Packet::Close {
                                stream_id,
                                reason: 0x03,
                            }).await;
                            break;
                        }
                    }
                }
            });

            let mut sent_bytes_since_continue = 0u32;
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    StreamCmd::Data(payload) => {
                        if let Err(e) = socket.send(&payload).await {
                            warn!(?e, stream_id, "udp send error");
                            let _ = tx.send(Packet::Close {
                                stream_id,
                                reason: 0x03,
                            }).await;
                            break;
                        }
                        sent_bytes_since_continue = sent_bytes_since_continue.saturating_add(
                            payload.len() as u32
                        );
                        if sent_bytes_since_continue >= continue_threshold_bytes {
                            let _ = tx.send(Packet::Continue {
                                stream_id,
                                remaining: buffer_bytes,
                            }).await;
                            sent_bytes_since_continue = 0;
                        }
                    }
                    StreamCmd::Close(reason) => {
                        let _ = tx.send(Packet::Close { stream_id, reason }).await;
                        break;
                    }
                    StreamCmd::Resize(_, _) => {}
                }
            }
        }
        Err(e) => {
            warn!(?e, stream_id, "udp bind failed");
            let _ = tx.send(Packet::Close {
                stream_id,
                reason: 0x44,
            }).await;
        }
    }
}

async fn handle_twisp(
    stream_id: u32,
    cmd: String,
    tx: mpsc::Sender<Packet>,
    root: String,
    buffer_bytes: u32,
    continue_threshold_bytes: u32,
    mut rx: mpsc::Receiver<StreamCmd>
) {
    let mut full_cmd = PathBuf::from(root);
    full_cmd.push(cmd.trim_start_matches('/'));
    let spawn_result = portable_pty
        ::native_pty_system()
        .openpty(portable_pty::PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .and_then(|pair| {
            let cmd_path = full_cmd.to_string_lossy().to_string();
            let builder = CommandBuilder::new(cmd_path);
            pair.slave.spawn_command(builder).map(|child| (pair, child))
        });

    match spawn_result {
        Ok((pair, _child)) => {
            let _ = tx.send(Packet::Continue {
                stream_id,
                remaining: buffer_bytes,
            }).await;

            let reader = pair.master.try_clone_reader().expect("pty reader");
            let writer = pair.master.take_writer().expect("pty writer");

            let read_tx = tx.clone();
            tokio::task::spawn_blocking(move || {
                let mut reader = reader;
                let mut buf = vec![0u8; 65536];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => {
                            let _ = read_tx.blocking_send(Packet::Close {
                                stream_id,
                                reason: 0x02,
                            });
                            break;
                        }
                        Ok(n) => {
                            let _ = read_tx.blocking_send(Packet::Data {
                                stream_id,
                                payload: Bytes::copy_from_slice(&buf[..n]),
                            });
                        }
                        Err(e) => {
                            warn!(?e, stream_id, "twisp read error");
                            let _ = read_tx.blocking_send(Packet::Close {
                                stream_id,
                                reason: 0x03,
                            });
                            break;
                        }
                    }
                }
            });

            let writer = Arc::new(Mutex::new(writer));
            let mut sent_since_continue = 0u32;
            let mut sent_bytes_since_continue = 0u32;
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    StreamCmd::Data(payload) => {
                        let writer = writer.clone();
                        let data = payload.to_vec();
                        let write_res = tokio::task::spawn_blocking(move || {
                            let mut guard = writer.blocking_lock();
                            guard.write_all(&data)
                        }).await;

                        match write_res {
                            Ok(Ok(())) => {
                                sent_since_continue = sent_since_continue.saturating_add(1);
                                sent_bytes_since_continue =
                                    sent_bytes_since_continue.saturating_add(payload.len() as u32);
                                if sent_bytes_since_continue >= continue_threshold_bytes {
                                    let _ = tx.send(Packet::Continue {
                                        stream_id,
                                        remaining: buffer_bytes,
                                    }).await;
                                    sent_since_continue = 0;
                                    sent_bytes_since_continue = 0;
                                }
                            }
                            Ok(Err(e)) => {
                                warn!(?e, stream_id, "twisp write error");
                                let _ = tx.send(Packet::Close {
                                    stream_id,
                                    reason: 0x03,
                                }).await;
                                break;
                            }
                            Err(join_err) => {
                                warn!(?join_err, stream_id, "twisp write join error");
                                let _ = tx.send(Packet::Close {
                                    stream_id,
                                    reason: 0x03,
                                }).await;
                                break;
                            }
                        }
                    }
                    StreamCmd::Resize(rows, cols) => {
                        let _ = pair.master.resize(portable_pty::PtySize {
                            rows,
                            cols,
                            pixel_width: 0,
                            pixel_height: 0,
                        });
                    }
                    StreamCmd::Close(reason) => {
                        let _ = tx.send(Packet::Close { stream_id, reason }).await;
                        break;
                    }
                }
            }
        }
        Err(e) => {
            warn!(?e, stream_id, "twisp spawn failed");
            let _ = tx.send(Packet::Close {
                stream_id,
                reason: 0x44,
            }).await;
        }
    }
}
