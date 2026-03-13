use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Cursor;

use anyhow::Result;
use async_trait::async_trait;
use futures::TryFutureExt;
use tracing::trace;

#[cfg(feature = "rustls-tls")]
use {
    std::sync::Arc,
    tokio_rustls::{
        rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
        TlsConnector,
    },
};

#[cfg(all(feature = "rustls-tls", feature = "rustls-tls-aws-lc"))]
use tokio_rustls::rustls::client::{EchConfig, EchMode};
#[cfg(all(feature = "rustls-tls", feature = "rustls-tls-aws-lc"))]
use tokio_rustls::rustls::pki_types::{pem::PemObject, EchConfigListBytes};

#[cfg(feature = "openssl-tls")]
use {
    openssl::ssl::{Ssl, SslConnector, SslMethod},
    std::pin::Pin,
    std::sync::Once,
    tokio_openssl::SslStream,
};

use crate::{app::SyncDnsClient, proxy::*, session::Session};

#[cfg(feature = "rustls-tls")]
mod dangerous {
    use tokio_rustls::rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, Error, SignatureScheme,
    };

    #[derive(Debug)]
    pub(super) struct NotVerified;

    impl ServerCertVerifier for NotVerified {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> core::result::Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

pub struct Handler {
    server_name: String,
    alpns: Vec<String>,
    certificate: Option<String>,
    certificate_key: Option<String>,
    insecure: bool,
    fixed_ech_config_list: Option<String>,
    ech_disable_dns_lookup: bool,
    dns_client: SyncDnsClient,
    ech_enabled: bool,
    #[cfg(feature = "rustls-tls")]
    tls_config: Option<Arc<ClientConfig>>,
    #[cfg(feature = "openssl-tls")]
    ssl_connector: Option<SslConnector>,
}

impl Handler {
    #[cfg(feature = "rustls-tls")]
    fn build_rustls_config(
        alpns: &[String],
        certificate: Option<&String>,
        certificate_key: Option<&String>,
        insecure: bool,
        ech_config_list: Option<&str>,
    ) -> Result<Arc<ClientConfig>> {
        let mut roots = RootCertStore::empty();
        if let Some(cert) = certificate {
            if cert.contains("-----BEGIN") {
                let mut pem = BufReader::new(Cursor::new(cert.as_bytes()));
                for cert in rustls_pemfile::certs(&mut pem) {
                    roots.add(cert?)?;
                }
            } else {
                let mut pem = BufReader::new(File::open(cert).map_err(|e| {
                    anyhow::anyhow!("load certificates from {} failed: {}", cert, e)
                })?);
                for cert in rustls_pemfile::certs(&mut pem) {
                    roots.add(cert?)?;
                }
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        #[cfg(feature = "rustls-tls-aws-lc")]
        let provider = rustls::crypto::aws_lc_rs::default_provider().into();
        #[cfg(not(feature = "rustls-tls-aws-lc"))]
        let provider = rustls::crypto::ring::default_provider().into();

        let builder = ClientConfig::builder_with_provider(provider);
        #[cfg(feature = "rustls-tls-aws-lc")]
        let builder = if let Some(ech_config_list) = ech_config_list {
            let ech_config_list = decode_ech_config_list(ech_config_list)?;
            let ech_config = EchConfig::new(
                ech_config_list,
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            builder
                .with_ech(EchMode::Enable(ech_config))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
        } else {
            builder
                .with_safe_default_protocol_versions()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
        };
        #[cfg(not(feature = "rustls-tls-aws-lc"))]
        let builder = {
            if ech_config_list.is_some() {
                return Err(anyhow::anyhow!(
                    "tls outbound ech requires rustls-tls-aws-lc"
                ));
            }
            builder
                .with_safe_default_protocol_versions()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
        };

        let mut config = if insecure {
            let builder = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(dangerous::NotVerified));
            if certificate.is_some() {
                if certificate_key.is_some() {
                    builder.with_no_client_auth()
                } else {
                    builder.with_no_client_auth()
                }
            } else {
                builder.with_no_client_auth()
            }
        } else {
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        for alpn in alpns {
            config.alpn_protocols.push(alpn.as_bytes().to_vec());
        }
        Ok(Arc::new(config))
    }

    #[cfg(feature = "rustls-tls")]
    fn resolve_selected_ech_config_list(
        name: &str,
        fixed_ech_config_list: Option<&str>,
        auto_result: Option<anyhow::Result<String>>,
    ) -> io::Result<Option<String>> {
        match auto_result {
            Some(Ok(value)) => {
                trace!("ech source for {}: https/svcb dns record", name);
                Ok(Some(value))
            }
            Some(Err(err)) => {
                if let Some(fixed) = fixed_ech_config_list {
                    trace!(
                        "auto ech fetch failed for {}, fallback to fixed ech config: {}",
                        name,
                        err
                    );
                    Ok(Some(fixed.to_string()))
                } else {
                    trace!(
                        "auto ech fetch failed for {}, no fixed ech config available: {}",
                        name,
                        err
                    );
                    Err(io::Error::other(format!(
                        "auto ech fetch failed for {}: {}",
                        name, err
                    )))
                }
            }
            None => {
                if fixed_ech_config_list.is_some() {
                    trace!("ech source for {}: fixed ech config", name);
                } else {
                    trace!("ech source for {}: none", name);
                }
                Ok(fixed_ech_config_list.map(str::to_string))
            }
        }
    }

    #[cfg(feature = "rustls-tls")]
    fn should_skip_ech_dns_lookup_for_session(sess: &Session) -> bool {
        sess.inbound_tag == "dnsclient"
    }

    #[cfg(feature = "rustls-tls")]
    async fn select_ech_config_list(
        &self,
        name: &str,
        allow_dns_lookup: bool,
    ) -> io::Result<Option<String>> {
        if !self.ech_enabled {
            trace!("ech source for {}: none", name);
            return Ok(None);
        }
        if self.ech_disable_dns_lookup {
            if let Some(fixed) = self.fixed_ech_config_list.as_deref() {
                trace!("ech source for {}: fixed ech config", name);
                return Ok(Some(fixed.to_string()));
            }
            trace!("ech source for {}: none", name);
            return Ok(None);
        }
        let auto_result = if allow_dns_lookup {
            let dns_client = self.dns_client.read().await;
            Some(dns_client.lookup_ech_config_list(name).await)
        } else {
            trace!(
                "ech source for {}: fixed-or-none (dns lookup skipped)",
                name
            );
            None
        };
        Self::resolve_selected_ech_config_list(
            name,
            self.fixed_ech_config_list.as_deref(),
            auto_result,
        )
    }

    pub fn new(
        server_name: String,
        alpns: Vec<String>,
        certificate: Option<String>,
        certificate_key: Option<String>,
        insecure: bool,
        ech: bool,
        ech_disable_dns_lookup: bool,
        ech_config_list: Option<String>,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        let mut handler = Handler {
            server_name,
            alpns: alpns.clone(),
            certificate: certificate.clone(),
            certificate_key: certificate_key.clone(),
            insecure,
            fixed_ech_config_list: ech_config_list.clone(),
            ech_disable_dns_lookup,
            dns_client,
            ech_enabled: ech,
            #[cfg(feature = "rustls-tls")]
            tls_config: None,
            #[cfg(feature = "openssl-tls")]
            ssl_connector: None,
        };

        #[cfg(feature = "rustls-tls")]
        {
            #[cfg(feature = "rustls-tls-aws-lc")]
            {
                if handler.ech_enabled {
                    tracing::trace!("tls outbound ech configured");
                } else {
                    tracing::trace!("tls outbound ech not configured");
                }
            }
            #[cfg(not(feature = "rustls-tls-aws-lc"))]
            {
                handler.ech_enabled = false;
            }
            handler.tls_config = Some(Self::build_rustls_config(
                &alpns,
                certificate.as_ref(),
                certificate_key.as_ref(),
                insecure,
                if handler.ech_enabled {
                    ech_config_list.as_deref()
                } else {
                    None
                },
            )?);
        }

        #[cfg(feature = "openssl-tls")]
        {
            {
                static ONCE: Once = Once::new();
                ONCE.call_once(|| unsafe { openssl_probe::init_openssl_env_vars() });
            }
            let mut builder =
                SslConnector::builder(SslMethod::tls()).expect("create ssl connector failed");
            if !alpns.is_empty() {
                let wire = alpns
                    .iter()
                    .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
                    .collect::<Vec<Vec<u8>>>()
                    .concat();
                builder.set_alpn_protos(&wire).expect("set alpn failed");
            }
            if insecure {
                builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
            }
            handler.ssl_connector = Some(builder.build());
        }
        Ok(handler)
    }
}

#[cfg(all(feature = "rustls-tls", feature = "rustls-tls-aws-lc"))]
fn decode_ech_config_list(ech_config_list: &str) -> io::Result<EchConfigListBytes<'static>> {
    let ech_config_list = ech_config_list.trim();
    if ech_config_list.starts_with("-----BEGIN") {
        return EchConfigListBytes::from_pem_slice(ech_config_list.as_bytes())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
            .map(EchConfigListBytes::into_owned);
    }
    let decoded = decode_base64(ech_config_list)?;
    let (decoded, _) = ensure_ech_config_list_bytes(decoded);
    Ok(EchConfigListBytes::from(decoded))
}

#[cfg(all(feature = "rustls-tls", any(feature = "rustls-tls-aws-lc", test)))]
fn ensure_ech_config_list_bytes(mut decoded: Vec<u8>) -> (Vec<u8>, bool) {
    if decoded.len() >= 2 {
        let declared = u16::from_be_bytes([decoded[0], decoded[1]]) as usize;
        if declared == decoded.len().saturating_sub(2) {
            return (decoded, false);
        }
    }

    if decoded.len() >= 4 && decoded[0] == 0xfe && decoded[1] == 0x0d {
        let len = decoded.len();
        if u16::try_from(len).is_ok() {
            let mut wrapped = Vec::with_capacity(len + 2);
            wrapped.extend_from_slice(&(len as u16).to_be_bytes());
            wrapped.append(&mut decoded);
            return (wrapped, true);
        }
    }

    (decoded, false)
}

#[cfg(all(feature = "rustls-tls", any(feature = "rustls-tls-aws-lc", test)))]
fn decode_base64(data: &str) -> io::Result<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    fn decode_chunk(chunk: &[u8; 4], output: &mut Vec<u8>) -> io::Result<()> {
        if chunk[0] == 64 || chunk[1] == 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            ));
        }
        output.push((chunk[0] << 2) | (chunk[1] >> 4));
        match (chunk[2], chunk[3]) {
            (64, 64) => Ok(()),
            (64, _) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            )),
            (c2, 64) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                Ok(())
            }
            (c2, c3) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                output.push(((c2 & 0x03) << 6) | c3);
                Ok(())
            }
        }
    }

    let mut output = Vec::with_capacity(data.len() * 3 / 4);
    let mut chunk = [0_u8; 4];
    let mut chunk_len = 0_usize;
    let mut seen_padding = false;

    for byte in data.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            seen_padding = true;
            chunk[chunk_len] = 64;
            chunk_len += 1;
        } else if let Some(decoded) = value(byte) {
            if seen_padding {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid base64 padding",
                ));
            }
            chunk[chunk_len] = decoded;
            chunk_len += 1;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 character",
            ));
        }

        if chunk_len == 4 {
            decode_chunk(&chunk, &mut output)?;
            chunk = [0_u8; 4];
            chunk_len = 0;
        }
    }

    match chunk_len {
        0 => Ok(output),
        2 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            Ok(output)
        }
        3 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push(((chunk[1] & 0x0f) << 4) | (chunk[2] >> 2));
            Ok(output)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid base64 length",
        )),
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    #[allow(unreachable_code)]
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        // TODO optimize, dont need copy
        let name = if !&self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        if let Some(stream) = stream {
            #[cfg(feature = "rustls-tls")]
            {
                let mut ech_config_selected = false;
                let mut ech_dns_lookup_skipped = false;
                let tls_config = {
                    if self.ech_enabled {
                        ech_dns_lookup_skipped = Self::should_skip_ech_dns_lookup_for_session(sess);
                        let selected_ech = self
                            .select_ech_config_list(&name, !ech_dns_lookup_skipped)
                            .await?;
                        ech_config_selected = selected_ech.is_some();
                        Self::build_rustls_config(
                            &self.alpns,
                            self.certificate.as_ref(),
                            self.certificate_key.as_ref(),
                            self.insecure,
                            selected_ech.as_deref(),
                        )
                        .map_err(|e| io::Error::other(format!("build tls config failed: {}", e)))?
                    } else {
                        self.tls_config
                            .as_ref()
                            .cloned()
                            .ok_or_else(|| io::Error::other("no tls backend available"))?
                    }
                };
                trace!(
                    "handling TLS {} with rustls, ech_enabled={}, ech_config_selected={}, ech_dns_lookup_skipped={}",
                    &name,
                    self.ech_enabled,
                    ech_config_selected,
                    ech_dns_lookup_skipped
                );
                let connector = TlsConnector::from(tls_config);
                let domain = ServerName::try_from(name.as_str()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid tls server name {}: {}", &name, e),
                    )
                })?;
                let tls_stream = connector
                    .connect(domain.to_owned(), stream)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("connect tls failed: {}", e),
                        )
                    })
                    .await?;
                // FIXME check negotiated alpn
                return Ok(Box::new(tls_stream));
            }
            #[cfg(feature = "openssl-tls")]
            if let Some(ssl_connector) = self.ssl_connector.as_ref() {
                trace!("handling TLS {} with openssl", &name);
                let mut ssl = Ssl::new(ssl_connector.context()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("new ssl failed: {}", e),
                    )
                })?;
                ssl.set_hostname(&name).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("set tls name failed: {}", e),
                    )
                })?;
                let mut stream = SslStream::new(ssl, stream).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("new ssl stream failed: {}", e),
                    )
                })?;
                Pin::new(&mut stream)
                    .connect()
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("connect ssl stream failed: {}", e),
                        )
                    })
                    .await?;
                return Ok(Box::new(stream));
            }
            Err(io::Error::other("no tls backend available"))
        } else {
            Err(io::Error::other("invalid tls input"))
        }
    }
}

#[cfg(all(test, feature = "rustls-tls"))]
mod tests {
    use anyhow::anyhow;
    use std::sync::Arc;

    use protobuf::MessageField;
    use tokio::sync::RwLock;

    use crate::{
        app::{dns_client::DnsClient, SyncDnsClient},
        session::Session,
    };

    use super::{decode_base64, ensure_ech_config_list_bytes, Handler};

    fn new_test_dns_client() -> SyncDnsClient {
        let mut dns = crate::config::Dns::new();
        dns.servers.push("1.1.1.1".to_string());
        let dns = MessageField::some(dns);
        Arc::new(RwLock::new(DnsClient::new(&dns).unwrap()))
    }

    #[test]
    fn test_decode_base64_standard_and_urlsafe() {
        assert_eq!(decode_base64("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_base64("AQI=").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("AQI").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("-_8=").unwrap(), vec![251, 255]);
    }

    #[test]
    fn test_decode_base64_invalid_input() {
        assert!(decode_base64("A").is_err());
        assert!(decode_base64("AA=A").is_err());
        assert!(decode_base64("AA$A").is_err());
    }

    #[test]
    fn test_ensure_ech_config_list_bytes_wrap_single_config() {
        let input = vec![0xfe, 0x0d, 0x00, 0x41];
        let (out, wrapped) = ensure_ech_config_list_bytes(input);
        assert!(wrapped);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x04);
        assert_eq!(&out[2..], &[0xfe, 0x0d, 0x00, 0x41]);
    }

    #[test]
    fn test_ensure_ech_config_list_bytes_keep_existing_list() {
        let input = vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x41];
        let (out, wrapped) = ensure_ech_config_list_bytes(input.clone());
        assert!(!wrapped);
        assert_eq!(out, input);
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_success() {
        let result = Handler::resolve_selected_ech_config_list(
            "example.com",
            Some("AQI="),
            Some(Ok("AQID".to_string())),
        )
        .unwrap();
        assert_eq!(result, Some("AQID".to_string()));
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_failed_fallback() {
        let result = Handler::resolve_selected_ech_config_list(
            "example.com",
            Some("AQI="),
            Some(Err(anyhow!("dns failed"))),
        )
        .unwrap();
        assert_eq!(result, Some("AQI=".to_string()));
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_failed_without_fallback() {
        let err = Handler::resolve_selected_ech_config_list(
            "example.com",
            None,
            Some(Err(anyhow!("dns failed"))),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("auto ech fetch failed for example.com: dns failed"));
    }

    #[test]
    fn test_should_skip_ech_dns_lookup_for_dnsclient_session() {
        let mut sess = Session::default();
        sess.inbound_tag = "dnsclient".to_string();
        assert!(Handler::should_skip_ech_dns_lookup_for_session(&sess));
        sess.inbound_tag = "socks".to_string();
        assert!(!Handler::should_skip_ech_dns_lookup_for_session(&sess));
    }

    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    #[test]
    fn test_new_with_ech_requires_aws_lc() {
        let result = Handler::new(
            "localhost".to_string(),
            vec![],
            None,
            None,
            false,
            true,
            false,
            Some("AQID".to_string()),
            new_test_dns_client(),
        );
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("rustls-tls-aws-lc"));
    }

    #[cfg(feature = "rustls-tls-aws-lc")]
    #[test]
    fn test_new_with_invalid_ech_config_list_fails() {
        let result = Handler::new(
            "localhost".to_string(),
            vec![],
            None,
            None,
            false,
            true,
            false,
            Some("$$$".to_string()),
            new_test_dns_client(),
        );
        assert!(result.is_err());
    }
}
