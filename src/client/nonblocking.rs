use std::io::{Error, ErrorKind, Result};
use std::marker::PhantomData;
use std::sync::{Arc};
use std::collections::HashMap;
use std::task::{Poll, Context};
use std::pin::Pin;
use std::net::SocketAddr;

use log::{error, debug, trace};

use futures::{Stream};

use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{UdpSocket};
use tokio::{task, time};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{channel, Sender, Receiver};

use openssl::ssl::{SslMethod, SslVerifyMode, SslFiletype};


use crate::Method;
use crate::message::packet::{Packet, ObserveOption};
use crate::message::response::{CoAPResponse, Status};
use crate::message::request::CoAPRequest;
use crate::message::IsMessage;

use super::RequestOptions;

pub const COAP_MTU: usize = 1600;

pub struct CoAPClientAsync<Transport> {
    int_tx: Sender<Vec<u8>>,
    message_id: u16,
    _listener: task::JoinHandle<Result<()>>,
    _transport: PhantomData<Transport>,
    rx_handles: Arc<Mutex<HashMap<u32, (SenderKind, Sender<CoAPResponse>)>>>,
}

#[derive(Clone, Debug, PartialEq)]
enum SenderKind {
    Request,
    Observer,
}

// https://github.com/fdeantoni/async-coap-dtls/blob/master/src/dtls/connector.rs


pub struct UdpStream {
    socket: tokio::net::UdpSocket,
}

impl From<tokio::net::UdpSocket> for UdpStream {
    fn from(socket: tokio::net::UdpSocket) -> Self {
        Self{ socket }
    }
}

impl std::io::Read for UdpStream {
    fn read(&mut self, buff: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        self.socket.try_recv(buff)
    }
}

impl std::io::Write for UdpStream {
    fn write(&mut self, buff: &[u8]) -> std::result::Result<usize, std::io::Error> { 
        self.socket.try_send(buff)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl AsyncRead for UdpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<()>> {
        match self.socket.poll_recv(cx, buf) {
            Poll::Ready(Ok(_n)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UdpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        self.socket.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl CoAPClientAsync<UdpStream> {
    /// EXPERIMENTAL: create a new CoAP client using the DTLS transport
    pub async fn new_dtls(peer: &str, ca_file: &str, cert_file: &str, key_file: &str) -> Result<Self> {
        // Bind UDP sockety
        let udp_socket = Self::udp_connect(peer).await?;

        // Bind UDP socket
        let udp_stream = UdpStream::from(udp_socket);

        // Setup openssl connector
        let mut ssl_builder = openssl::ssl::SslConnector::builder(SslMethod::dtls()).unwrap();

        ssl_builder.set_verify(SslVerifyMode::NONE);
        ssl_builder.set_ca_file(ca_file)?;
        ssl_builder.set_certificate_file(cert_file, SslFiletype::PEM)?;
        ssl_builder.set_private_key_file(key_file, SslFiletype::PEM)?;

        let ssl_conn = ssl_builder.build();

        // Coerce to native_tls
        let mut tls_builder = native_tls::TlsConnector::builder();
        tls_builder.danger_accept_invalid_hostnames(true);
        let tls_conn = tls_builder.from_openssl(ssl_conn);

        // Coerce to tokio_native_tls
        let async_tls_conn = tokio_native_tls::TlsConnector::from(tls_conn);

        // Attempt DTLS connection
        let tls_sock = async_tls_conn.connect(peer, udp_stream).await.unwrap();

        let (mut net_rx, mut net_tx) = tokio::io::split(tls_sock);

        let rx_handles = Arc::new(Mutex::new(HashMap::<u32, (SenderKind, Sender<CoAPResponse>)>::new()));
        let (int_tx, mut int_rx) = channel::<Vec<u8>>(10);

        // TODO: start listener task
        let handles = rx_handles.clone();
        let listener = tokio::task::spawn(async move {
            let mut buff = [0u8; COAP_MTU];

            loop {
                tokio::select!(
                    r = net_rx.read(&mut buff) => {
                        match r {
                            Ok(n) => {
                                debug!("net receive: {:?}", &buff[..n]);

                                let message = match Packet::from_bytes(&buff[..n]) {
                                    Ok(v) => CoAPResponse { message: v },
                                    Err(e) => {
                                        debug!("decode error: {:?}", e);
                                        continue;
                                    }
                                };

                                let token = Self::token_from_slice(message.get_token());

                                let handle = handles.lock().await.get(&token).map(|v| v.clone() );
                                match handle {
                                    Some((kind, tx)) => {
                                        tx.send(message).await.unwrap();

                                        if kind == SenderKind::Request {
                                            handles.lock().await.remove(&token);
                                        }
                                    },
                                    None => {
                                        debug!("unhandled response: {:?}", message);
                                        continue;
                                    }
                                }
                                
                            },
                            Err(e) => {
                                error!("net receive error: {:?}", e);
                                break;
                            }
                        }
                    },
                    Some(v) = int_rx.recv() => {
                        debug!("net tx: {:?}", v);
                        if let Err(e) = net_tx.write(&v[..]).await {
                            error!("net transmit error: {:?}", e);
                            break;
                        }
                    }
                )
            }

            Ok(())
        });

        Ok(Self{
            int_tx,
            _listener: listener,
            message_id: 0,
            _transport: PhantomData,
            rx_handles,
        })
    }
}

impl CoAPClientAsync<tokio::net::UdpSocket> {

    pub async fn new_udp(peer: &str) -> Result<Self> 
    {
        // Connect to UDP socket
        let udp_sock = Self::udp_connect(peer).await?;

        let rx_handles = Arc::new(Mutex::new(HashMap::<u32, (SenderKind, Sender<CoAPResponse>)>::new()));
        let (int_tx, mut int_rx) = channel::<Vec<u8>>(10);

        // TODO: start listener thread
        let handles = rx_handles.clone();
        let listener = tokio::task::spawn(async move {
            let mut buff = [0u8; COAP_MTU];

            loop {
                tokio::select!(
                    r = udp_sock.recv(&mut buff) => {
                        match r {
                            Ok(n) => {
                                debug!("net receive: {:?}", &buff[..n]);

                                let message = match Packet::from_bytes(&buff[..n]) {
                                    Ok(v) => CoAPResponse { message: v },
                                    Err(e) => {
                                        debug!("decode error: {:?}", e);
                                        continue;
                                    }
                                };

                                let token = Self::token_from_slice(message.get_token());

                                let handle = handles.lock().await.get(&token).map(|v| v.clone() );
                                match handle {
                                    Some((kind, tx)) => {
                                        tx.send(message).await.unwrap();

                                        if kind == SenderKind::Request {
                                            handles.lock().await.remove(&token);
                                        }
                                    },
                                    None => {
                                        debug!("unhandled response: {:?}", message);
                                        continue;
                                    }
                                }
                            },
                            Err(e) => {
                                error!("net receive error: {:?}", e);
                                break;
                            }
                        }
                    },
                    Some(v) = int_rx.recv() => {
                        debug!("net tx: {:?}", v);
                        if let Err(e) = udp_sock.send(&v[..]).await {
                            error!("net transmit error: {:?}", e);
                            break;
                        }
                    }
                )
            }

            Ok(())
        });

        Ok(Self{
            int_tx,
            _listener: listener,
            message_id: 0,
            _transport: PhantomData,
            rx_handles,
        })
    }
}


impl <T>CoAPClientAsync<T> {
     /// Helper to create UDP connections
     async fn udp_connect(peer: &str) -> Result<tokio::net::UdpSocket> {

        // Resolve peer address to determine local socket type
        let peer_addr = tokio::net::lookup_host(peer).await?.next();

        // Work out bind address
        let bind_addr = match peer_addr {
            Some(SocketAddr::V6(_)) => ":::0",
            Some(SocketAddr::V4(_)) => "0.0.0.0:0",
            None => {
                error!("No peer address found");
                return Err(Error::new(ErrorKind::NotFound, "no peer address found"));
            }
        };
        let peer_addr = peer_addr.unwrap();

        // Bind to local socket
        let udp_sock = UdpSocket::bind(bind_addr).await
            .map_err(|e| {
                error!("Error binding local socket: {:?}", e);
                e
            })?;

        debug!("Bound to socket: {}", udp_sock.local_addr()?);

        // Connect to remote socket
        udp_sock.connect(peer_addr).await?;

        Ok(udp_sock)
    }

    // Convenience method to perform a Get request
    pub async fn get(&mut self, resource: &str, options: &RequestOptions) -> Result<CoAPResponse> {
        let request = self.new_request(Method::Post, resource, None, options);

        self.request(&request, options).await
    }

    // Convenience method to perform a Put request
    pub async fn put(&mut self, resource: &str, data: &[u8], options: &RequestOptions) -> Result<CoAPResponse> {
        let request = self.new_request(Method::Put, resource, Some(data), options);

        self.request(&request, options).await
    }

    // Convenience method to perform a Post request
    pub async fn post(&mut self, resource: &str, data: &[u8], options: &RequestOptions) -> Result<CoAPResponse> {
        let request = self.new_request(Method::Post, resource, Some(data), options);

        self.request(&request, options).await
    }

    pub fn new_request(&mut self, method: Method, resource: &str, data: Option<&[u8]>, options: &RequestOptions) -> CoAPRequest {
        let message_id = self.message_id;
        self.message_id += 1;
        
        let mut request = CoAPRequest::new();
        request.set_message_id(message_id);
        request.set_method(method);
        request.set_path(resource);
        
        if let Some(d) = data {
            request.set_payload(d.to_vec());
        }

        request.set_token(options.token.clone());

        request
    }

    // Execute a CoAP request and return a response
    pub async fn request(&mut self, request: &CoAPRequest, options: &RequestOptions) -> Result<CoAPResponse> {
        debug!("{:?} resource: {:?}", request.get_method(), request.get_path());

        // Fetch token from message
        let token = Self::token_from_slice(request.get_token());
        
        // Generate response channel
        let (tx, mut rx) = channel(1);
        self.rx_handles.lock().await.insert(token, (SenderKind::Request, tx));

        // Execute request
        self.do_request(request.message.clone(), &mut rx, options).await
    }

    // Start observation on a topic
    pub async fn observe(&mut self, resource: &str, options: &RequestOptions) -> Result<CoAPObserverAsync> {

        debug!("Observe resource: {:?}", resource);

        // Setup registration message
        let mut register_req = self.new_request(Method::Get, resource, None, options);
        register_req.set_observe(vec![ObserveOption::Register as u8]);

        let token = Self::token_from_slice(register_req.get_token());

        // Setup response channel
        let (tx, mut rx) = channel(10);
        let tx1 = tx.clone();
        self.rx_handles.lock().await.insert(token, (SenderKind::Observer, tx));

        let register_resp = self.do_request(register_req.message, &mut rx, options).await?;

        // Handle response errors (expect a 2.05 on successful observe)
        if *register_resp.get_status() != Status::Content {
            // TODO: remove response channel
            return Err(Error::new(ErrorKind::NotFound, format!("Unexpected status code {:?}", register_resp.get_code())));
        }

        // Forward first response to observer
        tx1.send(register_resp).await.unwrap();

        Ok(CoAPObserverAsync{
            topic: resource.to_string(),
            token, rx
        })
    }

    pub async fn unobserve(&mut self, observer: CoAPObserverAsync) -> Result<()> {
        
        debug!("Unobserve resource: {:?}", observer.topic);

        // Send deregister packet
        let mut deregister_req = CoAPRequest::new();
        deregister_req.set_message_id(self.message_id());
        deregister_req.set_observe(vec![ObserveOption::Deregister as u8]);
        deregister_req.set_path(observer.topic.as_str());
        deregister_req.set_token(observer.token.to_be_bytes().to_vec());

        let deregister_resp = self.request(&deregister_req, &RequestOptions::default()).await?;

        // TODO: anything to check here?
        let _ = deregister_resp;

        Ok(())
    }

    async fn do_request(&mut self, message: Packet, rx: &mut Receiver<CoAPResponse>, options: &RequestOptions) -> Result<CoAPResponse> {

        for _i in 0..options.retries {

            // Encode message
            let encoded = message.to_bytes().map_err(|_e| Error::new(ErrorKind::InvalidInput, "packet error"))?;

            // Send encoded data
            trace!("Transmit data: {:?}", encoded);

            if let Err(e) = self.int_tx.send(encoded).await {
                error!("request error: {:?}", e);
                continue;
            }

            // Await response
            match time::timeout(options.timeout, rx.recv()).await {
                Ok(Some(v)) => return Ok(v),
                _ => continue,
            }
        }

        Err(Error::new(ErrorKind::TimedOut, "no response"))
    }

    fn token_from_slice(v: &[u8]) -> u32 {
        let mut token_raw = [0u8; 4];

        token_raw[..v.len()].copy_from_slice(v);

        u32::from_be_bytes(token_raw)
    }

    fn message_id(&mut self) -> u16 {
        let id = self.message_id;
        self.message_id += 1;
        id
    }
}

/// CoAPObserverAsync object can be polled for subscriptions
pub struct CoAPObserverAsync {
    topic: String,
    token: u32,
    rx: Receiver<CoAPResponse>,
}

impl CoAPObserverAsync {
    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub fn token(&self) -> u32 {
        self.token
    }
}

impl Stream for CoAPObserverAsync {
    type Item = CoAPResponse;

    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.rx).poll_recv(ctx)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;
    use futures::StreamExt;
    
    use crate::*;
    use super::*;


    #[tokio::test]
    async fn test_get() {
        let mut client = CoAPClientAsync::new_udp("coap.me:5683").await.unwrap();

        let resp = client.get("hello", &RequestOptions::default()).await.unwrap();
        assert_eq!(resp.message.payload, b"world".to_vec());
    }

    async fn request_handler(req: CoAPRequest) -> Option<CoAPResponse> {
        debug!("test server request: {:?}", req);

        let uri_path_list = req.get_option(CoAPOption::UriPath).unwrap().clone();
        assert_eq!(uri_path_list.len(), 1);

        match req.response {
            Some(mut response) => {
                response.set_payload(uri_path_list.front().unwrap().clone());
                Some(response)
            }
            _ => None,
        }
    }

    #[tokio::test]
    async fn test_observe() {
        let opts = RequestOptions::default();

        // Setup server
        let server_port = server::test::spawn_server(request_handler).recv().unwrap();

        // Setup client
        let mut client = CoAPClientAsync::new_udp(("0.0.0.0", server_port)).await.unwrap();

        // Put initial data
        client.put("test", b"hello world 1", &opts).await.unwrap();

        // Initiate observation
        let mut observe = client.observe("test", &opts).await.unwrap();

        // Await response
        let resp = time::timeout(Duration::from_secs(10), observe.next()).await.unwrap();

        println!("RX 1: {:?}", resp);

        assert_eq!(resp.unwrap().message.payload, b"hello world 1".to_vec());

        // Send request
        client.put("test", b"hello world 2", &opts).await.unwrap();

        let resp = time::timeout(Duration::from_secs(10), observe.next()).await.unwrap();

        println!("RX 2: {:?}", resp);

        assert_eq!(resp.unwrap().message.payload, b"hello world 2".to_vec());
    }
}