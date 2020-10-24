use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    common::dns_client::DnsClient,
    proxy::{stream::SimpleStream, ProxyStream, ProxyTcpHandler},
    session::Session,
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
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        Some((self.address.clone(), self.port, self.bind_addr.clone()))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let uuid = Uuid::parse_str(&self.uuid).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("parse uuid failed: {}", e))
        })?;
        let mut request_header = RequestHeader {
            version: 0x1,
            command: vmess::REQUEST_COMMAND_TCP,
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
        Ok(Box::new(SimpleStream(stream)))
    }
}
