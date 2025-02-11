use std::io::{Error as IoError, Result as IoResult, ErrorKind};
use std::env;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{DerefMut};
use std::pin::{Pin};
use std::str::{self, FromStr};
use std::sync::{Arc};
use std::task::{Context, Poll, ready};
use std::future::{Future};
use std::collections::HashMap;

use h2::{Error as H2Error, SendStream, RecvStream, Reason};
use h2::client::{Builder as H2ClientBuilder, SendRequest, ResponseFuture};
use h2::server::{Builder as H2ServerBuilder, SendResponse};
use http::{Uri, Request, Response};
use bytes::{Bytes};
use serde::{Deserialize};
use tokio::fs::{File};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex};
use tokio::task::{JoinHandle};
use tokio::time::{Duration, Instant, Sleep, sleep};
use tokio_native_tls::{TlsConnector as AsyncTlsConnector};
use tokio_native_tls::native_tls::{TlsConnector, Protocol, Error as TlsError};
use ip_network_table_deps_treebitmap::IpLookupTable;


#[derive(Debug)]
enum Error {
  IO(IoError),
  H2(H2Error),
}
impl std::error::Error for Error {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Error::IO(e) => Some(e),
      Error::H2(e) => Some(e),
    }
  }
}
impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}", self)
  }
}

impl From<ErrorKind> for Error {
  fn from(e: ErrorKind) -> Self {
    Error::IO(e.into())
  }
}
impl From<IoError> for Error {
  fn from(e: IoError) -> Self {
    Error::IO(e)
  }
}
impl From<H2Error> for Error {
  fn from(e: H2Error) -> Self {
    Error::H2(e)
  }
}
impl From<TlsError> for Error {
  fn from(e: TlsError) -> Self {
    Error::IO(IoError::new(ErrorKind::ConnectionRefused, e))
  }
}
type Result<T> = std::result::Result<T, Error>;


trait Reader: AsyncRead + Unpin {}
impl<T: AsyncRead + Unpin> Reader for T {}
trait Writer: AsyncWrite + Unpin {}
impl<T: AsyncWrite + Unpin> Writer for T {}
enum Duplex {
  Tcp(TcpStream),
  H2s(H2Reader, H2Writer, Arc<()>),
}
#[derive(Clone, Copy)]
struct Forword(&'static str);
impl Forword {
  async fn pipe2(self, c: Duplex, s: Duplex) {
    match (c, s) {
      (Duplex::Tcp(mut c), Duplex::Tcp(mut s)) => {
         let (cr, cw) = c.split();
         let (sr, sw) = s.split();
         self.pipe4(cr, cw, sr, sw).await;
      },
      (Duplex::Tcp(mut c), Duplex::H2s(sr, sw, _y)) => {
         let (cr, cw) = c.split();
         self.pipe4(cr, cw, sr, sw).await;
      },
      (Duplex::H2s(cr, cw, _x), Duplex::Tcp(mut s)) => {
         let (sr, sw) = s.split();
         self.pipe4(cr, cw, sr, sw).await;
      },
      (Duplex::H2s(cr, cw, _x), Duplex::H2s(sr, sw, _y)) => {
        self.pipe4(cr, cw, sr, sw).await;
      },
    };
  }

  async fn pipe4(self, cr: impl Reader, cw: impl Writer, sr: impl Reader, sw: impl Writer) {
    let (c2s, s2c) = tokio::join!(self.forword(cr, sw), self.forword(sr, cw));
    if let Err(e) = c2s {
      println!("{}.c2s error {:?}", self.0, e);
    }
    if let Err(e) = s2c {
      println!("{}.s2c error {:?}", self.0, e);
    }
  }

  async fn forword(self, r: impl Reader, mut w: impl Writer) -> Result<()> {
    let mut d = vec![0u8; 65536];
    let mut r = TimedIo::new(r, 5*60);
    loop {
      match r.read(&mut d).await? {
        0 => break,
        n => w.write_all(&d[0..n]).await?,
      };
    }
    w.shutdown().await?;
    Ok(())
  }
}

struct Client {
  pool: Mutex<ClientPool>,
  rules: ClientRules,
}
impl Client {
  fn new(server: ServerUri, rules: ClientRules) -> Self {
    let pool = ClientPool::new(server);
    Self{pool: Mutex::new(pool), rules}
  }

  async fn serve(self, port: u16) -> Result<()> {
    let client = Arc::new(self);
    let listener = TcpListener::bind(("localhost", port)).await?;
    loop {
        let (socket, _) = listener.accept().await?;
        let c = Arc::clone(&client);
        tokio::spawn(async move { c.handle(socket).await });
    }
  }

  async fn handle(&self, mut cs: TcpStream) {
    let (host, port) = match self.socks(&mut cs).await {
      Ok(hp) => hp,
      Err(e) => return println!("client socks error {}", e),
    };

    let cs = Duplex::Tcp(cs);
    let ss = match self.connect(&host, port).await {
      Ok(ss) => ss,
      Err(e) => return println!("client connect error {}, {:?}", e, host),
    };
    Forword("client").pipe2(cs, ss).await;
    println!("client finish {:?}", host);
  }

  async fn socks(&self, cs: &mut TcpStream) -> Result<(Host, u16)> {
    let mut d = [0u8; 256];
    let v = cs.read_u8().await?;
    let m = cs.read_u8().await? as usize;
    cs.read_exact(&mut d[0..m]).await?;
    if !(v == 5 && d[0..m].contains(&0)) {
      return Err(ErrorKind::InvalidData.into());
    }

    cs.write_all(&[5u8, 0u8]).await?;
    let v = cs.read_u8().await?;
    let c = cs.read_u8().await?;
    let _ = cs.read_u8().await?;
    let t = cs.read_u8().await?;
    if !(v == 5 && c == 1) {
      return Err(ErrorKind::InvalidData.into());
    }
    let host = if t == 1 {
      Host::Ipv4(Ipv4Addr::from_bits(cs.read_u32().await?))
    } else if t == 3 {
      let n = cs.read_u8().await? as usize;
      cs.read_exact(&mut d[0..n]).await?;
      let s = str::from_utf8(&d[0..n]).map_err(|_| ErrorKind::InvalidData)?;
      Host::Name(String::from(s))
    } else if t == 4 {
      Host::Ipv6(Ipv6Addr::from_bits(cs.read_u128().await?))
    } else {
      return Err(ErrorKind::InvalidData.into());
    };
    let port = cs.read_u16().await?;
    cs.write_all(&[5u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]).await?;
    Ok((host, port))
  }

  async fn connect(&self, host: &Host, port: u16) -> Result<Duplex> {
    if self.rules.proxy(host) {
      println!("client proxy {:?}", host);
      let target = match host {
        Host::Name(h) => format!("{}:{}", h, port),
        Host::Ipv4(h) => format!("{}:{}", h, port),
        Host::Ipv6(h) => format!("[{}]:{}", h, port),
      };
      self.pool.lock().await.connect(&target).await
    } else {
      println!("client direct {:?}", host);
      let tcp = match host {
        Host::Name(h) => TcpStream::connect((h.as_str(), port)).await?,
        Host::Ipv4(h) => TcpStream::connect((*h, port)).await?,
        Host::Ipv6(h) => TcpStream::connect((*h, port)).await?,
      };
      Ok(Duplex::Tcp(tcp))
    }
  }
}

#[derive(Deserialize)]
struct RawRules {
  domains: Vec<String>,
  networks: Vec<String>,
}
struct ClientRules {
  domains: DomainLookupTable,
  v4networks: IpLookupTable<Ipv4Addr, ()>,
  v6networks: IpLookupTable<Ipv6Addr, ()>,
}
impl From<RawRules> for ClientRules {
  fn from(raw: RawRules) -> Self {
    let mut domains = DomainLookupTable::new();
    for n in raw.domains {
      domains.insert(&n);
    }
    let mut v4networks = IpLookupTable::new();
    let mut v6networks = IpLookupTable::new();
    for network in raw.networks {
      let mut split = network.split('/');
      let ip = IpAddr::from_str(split.next().unwrap()).unwrap();
      let mask = u32::from_str(split.next().unwrap()).unwrap();
      match ip {
        IpAddr::V4(ip) => v4networks.insert(ip, mask, ()),
        IpAddr::V6(ip) => v6networks.insert(ip, mask, ()),
      };
    }
    Self{domains, v4networks, v6networks}
  }
}
impl ClientRules {
  async fn load(file: &str) -> Self {
    let mut buf = vec![];
    let mut file = File::open(file).await.unwrap();
    file.read_to_end(&mut buf).await.unwrap();
    serde_json::from_slice::<RawRules>(&buf).unwrap().into()
  }
  fn proxy(&self, host: &Host) -> bool {
    !match host {
      Host::Name(n) => self.domains.contains(n),
      Host::Ipv4(p) => self.v4networks.longest_match(*p).is_some(),
      Host::Ipv6(p) => self.v6networks.longest_match(*p).is_some(),
    }
  }
}

struct DomainLookupTable {
  leaf: bool,
  nodes: HashMap<u8, DomainLookupTable>,
}
impl DomainLookupTable {
  fn new() -> Self {
    Self{leaf: false, nodes: HashMap::new()}
  }
  fn insert(&mut self, domain: &str) -> bool {
    let mut ptr = self;
    for v in domain.bytes().rev().chain(Some(b'.')) {
      ptr = ptr.nodes.entry(v).or_insert_with(DomainLookupTable::new);
      if ptr.leaf {
        return false;
      }
    }
    ptr.leaf = true;
    ptr.nodes.clear();
    return true;
  }

  fn contains(&self, domain: &str) -> bool {
    let mut ptr = self;
    for v in domain.bytes().rev().chain(Some(b'.')) {
      ptr = match ptr.nodes.get(&v) {
        Some(n) => n,
        None => return ptr.leaf,
      }
    }
    return true;
  }
}

struct ClientPool {
  server: ServerUri,
  pool: Vec<ClientConn>,
  tls: AsyncTlsConnector,
}
impl ClientPool {
  fn new(server: ServerUri) -> Self {
    let cc = TlsConnector::builder()
        .request_alpns(&["h2"])
        .min_protocol_version(Some(Protocol::Tlsv12))
        .build()
        .unwrap();
    let tls = AsyncTlsConnector::from(cc);
    Self{server, pool: vec![], tls}
  }

  async fn connect(&mut self, target: &str) -> Result<Duplex> {
    let uri = Uri::builder()
        .scheme("https")
        .authority(self.server.host.as_str())
        .path_and_query(self.server.path.as_str())
        .build()
        .unwrap();
    let req = Request::post(uri)
        .header("remote-target", target)
        .body(())
        .unwrap();
    self.acquire().await?.request(req)
  }

  async fn acquire(&mut self) -> Result<&mut ClientConn> {
    let idx;
    self.pool.retain(ClientConn::alive);
    if let Some(i) = self.pool.iter().position(ClientConn::avaiable) {
      idx = i;
      println!("client pool reuse {}", idx);
    } else {
      idx = self.pool.len();
      println!("client pool new {}", idx);
      self.pool.push(self.handshake().await?);
    }
    Ok(&mut self.pool[idx])
  }

  async fn handshake(&self) -> Result<ClientConn> {
    let host = self.server.host.as_str();
    let tcp = TcpStream::connect((host, self.server.port)).await?;
    if host == "localhost" {
      ClientConn::new(tcp).await
    } else {
      let tls = self.tls.connect(host, tcp).await?;
      ClientConn::new(tls).await
    }
  }
}

struct ClientConn {
  streams: Arc<()>,
  sender: SendRequest<Bytes>,
  task: JoinHandle<()>,
}
impl ClientConn {
  async fn new(sock: impl Reader + Writer + Send + 'static) -> Result<Self> {
    let sock = TimedIo::new(sock, 6*60);
    let (sender, conn) = H2ClientBuilder::new()
        .max_frame_size(1_000_000)
        .initial_window_size(4_000_000)
        .initial_connection_window_size(4_000_000)
        .handshake::<_, Bytes>(sock)
        .await?;
    let task = tokio::spawn(async move {
      if let Err(e) = conn.await {
        println!("client h2conn error {}", e);
      }
    });
    Ok(Self{streams: Arc::new(()), sender: sender.ready().await?, task})
  }

  fn request(&mut self, req: Request<()>) -> Result<Duplex> {
    println!("client request {} {}", self.sender.current_max_send_streams(), self.sender.current_max_recv_streams());
    let (res, send) = self.sender.send_request(req, false)?;
    let r = H2Reader::Head(res);
    let w = H2Writer{send};
    Ok(Duplex::H2s(r, w, Arc::clone(&self.streams)))
  }

  fn alive(&self) -> bool {
    !self.task.is_finished()
  }

  fn avaiable(&self) -> bool {
    self.alive() && Arc::strong_count(&self.streams) < 10
  }
}

#[derive(Clone, Copy)]
struct Server();
impl Server {
  async fn serve(self, port: u16) -> Result<()> {
    let listener = TcpListener::bind(("localhost", port)).await?;
    loop {
        let (sock, _) = listener.accept().await?;
        tokio::spawn(async move {
          if let Err(e) = self.handle(sock).await {
            println!("server h2conn.error {}", e);
          }
        });
    }
  }

  async fn handle(self, sock: TcpStream) -> Result<()> {
    let sock = TimedIo::new(sock, 6*60);
    let mut h2conn = H2ServerBuilder::new()
      .max_frame_size(1_000_000)
      .initial_window_size(4_000_000)
      .initial_connection_window_size(4_000_000)
      .handshake::<_, Bytes>(sock)
      .await?;
    while let Some(req) = h2conn.accept().await {
      let (req, sender) = req?;
      tokio::spawn(self.request(req, sender));
    }
    Ok(())
  }

  async fn request(self, req: Request<RecvStream>, mut sender: SendResponse<Bytes>) {
    let (parts, body) = req.into_parts();
    if let Some(target) = parts.headers.get("remote-target") {
      if let Ok(target) = target.to_str() {
        println!("server request {}", target);
        match TcpStream::connect(target).await {
          Ok(tcp) => {
            self.response(body, sender, tcp).await;
            return println!("server finish {}", target);
          },
          Err(e) => println!("server connect error {} {}", target, e),
        };
      }
    };
    sender.send_reset(Reason::REFUSED_STREAM);
  }

  async fn response(self, recv: RecvStream, mut sender: SendResponse<Bytes>, mut tcp: TcpStream) {
    let res = Response::builder()
        .header("Content-Type", "application/octet-stream")
        .body(())
        .unwrap();
    let send = sender.send_response(res, false).unwrap();

    let sr = H2Reader::Body(recv, Bytes::new());
    let sw = H2Writer{send};
    let (cr, cw) = tcp.split();
    Forword("server").pipe4(cr, cw, sr, sw).await;
  }
}


enum H2Reader {
  Head(ResponseFuture),
  Body(RecvStream, Bytes),
}
impl H2Reader {
  fn error(e: H2Error) -> IoResult<()> {
    if e.reason() == Some(Reason::NO_ERROR) {
      Ok(())
    } else {
      Err(H2Writer::error(e))
    }
  }
}
impl AsyncRead for H2Reader {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
    match self.deref_mut() {
      H2Reader::Head(head) => {
        let body = match ready!(Pin::new(head).poll(cx)) {
          Err(e) => return Poll::Ready(H2Reader::error(e)),
          Ok(r) => r.into_body(),
        };
        println!("reader head {}", body.stream_id().as_u32());
        self.set(H2Reader::Body(body, Bytes::new()));
        return self.poll_read(cx, buf);
      },
      H2Reader::Body(recv, data) => {
        loop {
          if data.is_empty() {
            match ready!(recv.poll_data(cx)) {
              None => return Poll::Ready(Ok(())),
              Some(Err(e)) => return Poll::Ready(H2Reader::error(e)),
              Some(Ok(d)) => *data = d,
            }
          } else {
            let n = std::cmp::min(buf.remaining(), data.len());
            let _ = recv.flow_control().release_capacity(n);
            buf.put_slice(&data.split_to(n));
            // println!("reader done {} {}", recv.stream_id().as_u32(), n);
            return Poll::Ready(Ok(()));
          }
        }
      },
    };
  }
}

struct H2Writer {
  send: SendStream<Bytes>,
}
impl H2Writer {
  fn error(e: H2Error) -> IoError {
    if e.is_io() {
      e.into_io().unwrap()
    } else if let Some(r) = e.reason() {
      IoError::new(ErrorKind::ConnectionAborted, r.description())
    } else {
      IoError::new(ErrorKind::ConnectionAborted, e)
    }
  }
}
impl AsyncWrite for H2Writer {
  fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
    self.send.reserve_capacity(buf.len());
    loop {
      match ready!(self.send.poll_capacity(cx)) {
        None => panic!("write poll none?"),
        Some(Err(e)) => return Poll::Ready(Err(H2Writer::error(e))),
        Some(Ok(n)) if n > 1024 || n >= buf.len() => {
          let data = Bytes::copy_from_slice(&buf[0..n]);
          // println!("writer done {} {}", self.send.stream_id().as_u32(), n);
          match self.send.send_data(data, false) {
            Ok(()) => return Poll::Ready(Ok(n)),
            Err(e) => return Poll::Ready(Err(H2Writer::error(e))),
          };
        },
        _ => (),
      };
    }
  }
  fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
    Poll::Ready(Ok(()))
  }
  fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
    let _ = self.send.send_data(Bytes::new(), true);
    Poll::Ready(Ok(()))
  }
}

struct TimedIo<S> {
  io: S,
  delay: Pin<Box<Sleep>>,
  duration: Duration,
}
impl<S> TimedIo<S> {
  fn new(io: S, secs: u64) -> Self {
    let duration = Duration::from_secs(secs);
    Self{io, delay: Box::pin(sleep(duration)), duration}
  }
  fn reset(&mut self) {
    self.delay.as_mut().reset(Instant::now() + self.duration);
  }
}
impl<S: Reader> AsyncRead for TimedIo<S> {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
    let ret = Pin::new(&mut self.io).poll_read(cx, buf);
    if ret.is_ready() {
      self.reset();
      ret
    } else {
      ready!(self.delay.as_mut().poll(cx));
      Poll::Ready(Ok(()))
    }
  }
}
impl<S: Writer> AsyncWrite for TimedIo<S> {
  fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
    self.reset();
    Pin::new(&mut self.io).poll_write(cx, buf)
  }
  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
    self.reset();
    Pin::new(&mut self.io).poll_flush(cx)
  }
  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
    self.reset();
    Pin::new(&mut self.io).poll_shutdown(cx)
  }
}

#[derive(Debug)]
enum Host {
  Name(String),
  Ipv4(Ipv4Addr),
  Ipv6(Ipv6Addr),
}
struct ServerUri {
  host: String,
  port: u16,
  path: String,
}
impl ServerUri {
  fn new(host: impl Into<String>, port: u16, path: impl Into<String>) -> Self {
    Self{host: host.into(), port, path: path.into()}
  }
}

#[tokio::main]
async fn main() {
  let args = env::args().skip(1).collect::<Vec<_>>();
  let args = args.iter().map(String::as_str).collect::<Vec<_>>();
  match args[..] {
    ["server", port] => {
      let port = u16::from_str(port).unwrap();
      Server().serve(port).await.unwrap();
    },
    ["client", lport, host, rport, path, config] => {
      let lport = u16::from_str(lport).unwrap();
      let rport = u16::from_str(rport).unwrap();
      let server = ServerUri::new(host, rport, path);
      let rules = ClientRules::load(config).await;
      Client::new(server, rules).serve(lport).await.unwrap();
    },
    ["test", port, config] => {
      let port = u16::from_str(port).unwrap();
      let server = ServerUri::new("localhost", 21773, "/test");
      let rules = ClientRules::load(config).await;
      let (a, b) = tokio::join!(
        Server().serve(21773),
        Client::new(server, rules).serve(port),
      );
      a.and(b).unwrap();
    },
    _ => panic!("usage"),
  };
}
