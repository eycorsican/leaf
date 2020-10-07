use std::{
    cmp::min,
    convert::TryFrom,
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::future::TryFutureExt;
use log::*;
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::{
    common::dns_client::DnsClient,
    proxy::{
        ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf, ProxyStream, ProxyUdpHandler,
        UdpTransportType,
    },
    session::{Session, SocksAddr},
};

use super::SocksAddr as VMessSocksAddr;
use super::*;

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub security: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl ProxyUdpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        Some((self.address.clone(), self.port, self.bind_addr.clone()))
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Stream
    }

    async fn connect<'a>(
        &'a self,
        sess: &'a Session,
        _datagram: Option<Box<dyn ProxyDatagram>>,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyDatagram>> {
        let target = match sess.destination {
            SocksAddr::Ip(addr) => VMessSocksAddr::from(addr),
            SocksAddr::Domain(ref domain, port) => match VMessSocksAddr::try_from((domain, port)) {
                Ok(addr) => addr,
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("invalid destination: {}", e),
                    ))
                }
            },
        };

        let uuid = if let Ok(v) = Uuid::parse_str(&self.uuid) {
            v
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid uuid"));
        };

        let mut request_header = RequestHeader {
            version: 0x1,
            command: vmess::REQUEST_COMMAND_UDP,
            option: vmess::REQUEST_OPTION_CHUNK_STREAM,
            security: vmess::SECURITY_TYPE_CHACHA20_POLY1305,
            address: target,
            uuid,
        };
        request_header.set_option(vmess::REQUEST_OPTION_CHUNK_MASKING);
        request_header.set_option(vmess::REQUEST_OPTION_GLOBAL_PADDING);

        let mut header_buf = BytesMut::new();

        let client_sess = ClientSession::new();
        request_header
            .encode(&mut header_buf, &client_sess)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("encode request header failed: {}", e),
                )
            })?;

        let enc_size_parser = ShakeSizeParser::new(&client_sess.request_body_iv);
        let enc = vmess::new_encryptor(
            self.security.as_str(),
            &client_sess.request_body_key,
            &client_sess.request_body_iv,
        )
        .map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("new encryptor failed: {}", e))
        })?;

        let dec_size_parser = ShakeSizeParser::new(&client_sess.response_body_iv);
        let dec = vmess::new_decryptor(
            self.security.as_str(),
            &client_sess.response_body_key,
            &client_sess.response_body_iv,
        )
        .map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("new decryptor failed: {}", e))
        })?;

        if let Some(mut stream) = stream {
            stream.write_all(&header_buf).await?; // write request

            let stream = VMessAuthStream::new(
                stream,
                client_sess,
                enc,
                enc_size_parser,
                dec,
                dec_size_parser,
            );

            let target = match sess.destination {
                SocksAddr::Ip(addr) => VMessSocksAddr::from(addr),
                SocksAddr::Domain(ref domain, port) => {
                    match VMessSocksAddr::try_from((domain, port)) {
                        Ok(addr) => addr,
                        Err(e) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("invalid destination: {}", e),
                            ))
                        }
                    }
                }
            };
            return Ok(Box::new(Datagram { stream, target }));
        }

        let ips = match self
            .dns_client
            .lookup_with_bind(String::from(&self.address), &self.bind_addr)
            .await
        {
            Ok(ips) => ips,
            Err(err) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("lookup {} failed: {}", &self.address, err),
                ));
            }
        };

        let mut last_err = None;

        for ip in ips {
            let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
            socket.bind(&self.bind_addr.into())?;
            let addr = SocketAddr::new(ip, self.port);
            match TcpStream::connect_std(socket.into_tcp_stream(), &addr).await {
                Ok(mut stream) => {
                    stream.write_all(&header_buf).await?; // write request

                    let stream = VMessAuthStream::new(
                        stream,
                        client_sess,
                        enc,
                        enc_size_parser,
                        dec,
                        dec_size_parser,
                    );

                    let target = match sess.destination {
                        SocksAddr::Ip(addr) => VMessSocksAddr::from(addr),
                        SocksAddr::Domain(ref domain, port) => {
                            match VMessSocksAddr::try_from((domain, port)) {
                                Ok(addr) => addr,
                                Err(e) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("invalid destination: {}", e),
                                    ))
                                }
                            }
                        }
                    };
                    return Ok(Box::new(Datagram { stream, target }));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "could not resolve to any address")
        }))
    }
}

pub struct Datagram<S> {
    stream: S,
    target: VMessSocksAddr,
}

impl<S> ProxyDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn ProxyDatagramRecvHalf>,
        Box<dyn ProxyDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf(r, self.target)),
            Box::new(DatagramSendHalf(w)),
        )
    }
}

pub struct DatagramRecvHalf<T>(ReadHalf<T>, VMessSocksAddr);

#[async_trait]
impl<T> ProxyDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // TODO optimize
        let mut buf2 = vec![0u8; 2 * 1024];
        let n = self.0.read(&mut buf2).await?;
        let to_write = min(n, buf.len());
        buf[..to_write].copy_from_slice(&buf2[..to_write]);
        let addr = match self.1 {
            VMessSocksAddr::Ip(addr) => addr,
            _ => {
                error!("unexpected domain address");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unexpected domain address in vmess udp",
                ));
            }
        };
        Ok((to_write, addr))
    }
}

pub struct DatagramSendHalf<T>(WriteHalf<T>);

#[async_trait]
impl<T> ProxyDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    async fn send_to(&mut self, buf: &[u8], _target: &SocketAddr) -> io::Result<usize> {
        self.0.write_all(&buf).map_ok(|_| buf.len()).await
    }
}
