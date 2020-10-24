use std::{cmp::min, io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::future::TryFutureExt;
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use uuid::Uuid;

use crate::{
    common::dns_client::DnsClient,
    proxy::{
        ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf, ProxyStream, ProxyUdpHandler,
        UdpTransportType,
    },
    session::{Session, SocksAddr},
};

use super::crypto::*;
use super::vmess;
use super::vmess::*;

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
        let uuid = Uuid::parse_str(&self.uuid).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("parse uuid failed: {}", e))
        })?;
        let mut request_header = RequestHeader {
            version: 0x1,
            command: vmess::REQUEST_COMMAND_UDP,
            option: vmess::REQUEST_OPTION_CHUNK_STREAM,
            security: vmess::SECURITY_TYPE_CHACHA20_POLY1305,
            address: sess.destination.clone(),
            uuid,
        };
        request_header.set_option(vmess::REQUEST_OPTION_CHUNK_MASKING);
        request_header.set_option(vmess::REQUEST_OPTION_GLOBAL_PADDING);

        match self.security.to_lowercase().as_str() {
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
                request_header.security = vmess::SECURITY_TYPE_CHACHA20_POLY1305;
            }
            "aes-128-gcm" => {
                request_header.security = vmess::SECURITY_TYPE_AES128_GCM;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("unsupported cipher: {}", &self.security),
                ))
            }
        }

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
        let enc = new_encryptor(
            self.security.as_str(),
            &client_sess.request_body_key,
            &client_sess.request_body_iv,
        )
        .map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("new encryptor failed: {}", e))
        })?;

        let dec_size_parser = ShakeSizeParser::new(&client_sess.response_body_iv);
        let dec = new_decryptor(
            self.security.as_str(),
            &client_sess.response_body_key,
            &client_sess.response_body_iv,
        )
        .map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("new decryptor failed: {}", e))
        })?;

        let mut stream = if let Some(stream) = stream {
            stream
        } else {
            self.dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?
        };

        stream.write_all(&header_buf).await?; // write request
        let stream = VMessAuthStream::new(
            stream,
            client_sess,
            enc,
            enc_size_parser,
            dec,
            dec_size_parser,
            16, // FIXME
        );
        Ok(Box::new(Datagram {
            stream,
            target: sess.destination.clone(),
        }))
    }
}

pub struct Datagram<S> {
    stream: S,
    target: SocksAddr,
}

impl<S> ProxyDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
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

pub struct DatagramRecvHalf<T>(ReadHalf<T>, SocksAddr);

#[async_trait]
impl<T> ProxyDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // TODO optimize
        let mut buf2 = vec![0u8; 2 * 1024];
        let n = self.0.read(&mut buf2).await?;
        let to_write = min(n, buf.len());
        buf[..to_write].copy_from_slice(&buf2[..to_write]);
        let addr = match self.1 {
            SocksAddr::Ip(addr) => addr,
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
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], _target: &SocketAddr) -> io::Result<usize> {
        self.0.write_all(&buf).map_ok(|_| buf.len()).await
    }
}
