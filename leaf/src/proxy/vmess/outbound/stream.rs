use std::io;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{proxy::*, session::*};

use super::crypto::*;
use super::protocol::*;
use super::vmess_stream::*;

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub security: String,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let uuid = Uuid::parse_str(&self.uuid).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("parse uuid failed: {}", e))
        })?;
        let mut request_header = RequestHeader {
            version: 0x1,
            command: REQUEST_COMMAND_TCP,
            option: REQUEST_OPTION_CHUNK_STREAM,
            security: SECURITY_TYPE_CHACHA20_POLY1305,
            address: sess.destination.clone(),
            uuid,
        };
        request_header.set_option(REQUEST_OPTION_CHUNK_MASKING);
        request_header.set_option(REQUEST_OPTION_GLOBAL_PADDING);

        match self.security.to_lowercase().as_str() {
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
                request_header.security = SECURITY_TYPE_CHACHA20_POLY1305;
            }
            "aes-128-gcm" => {
                request_header.security = SECURITY_TYPE_AES128_GCM;
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

        let mut stream =
            stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;

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
        Ok(Box::new(stream))
    }
}
