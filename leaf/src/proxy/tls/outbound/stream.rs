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

#[cfg(feature = "openssl-tls")]
use {
    openssl::ssl::{Ssl, SslConnector, SslMethod},
    std::pin::Pin,
    std::sync::Once,
    tokio_openssl::SslStream,
};

use crate::{proxy::*, session::Session};

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
    #[cfg(feature = "rustls-tls")]
    tls_config: Option<Arc<ClientConfig>>,
    #[cfg(feature = "openssl-tls")]
    ssl_connector: Option<SslConnector>,
}

impl Handler {
    pub fn new(
        server_name: String,
        alpns: Vec<String>,
        certificate: Option<String>,
        certificate_key: Option<String>,
        insecure: bool,
    ) -> Result<Self> {
        let mut handler = Handler {
            server_name,
            #[cfg(feature = "rustls-tls")]
            tls_config: None,
            #[cfg(feature = "openssl-tls")]
            ssl_connector: None,
        };

        #[cfg(feature = "rustls-tls")]
        {
            let mut roots = RootCertStore::empty();
            if let Some(cert) = certificate.as_ref() {
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

            let builder = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

            let mut config = if insecure {
                let builder = builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(dangerous::NotVerified));
                if let Some(_certificate) = certificate {
                    if let Some(_certificate_key) = certificate_key {
                        // FIXME support client auth with insecure
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
            for alpn in &alpns {
                config.alpn_protocols.push(alpn.as_bytes().to_vec());
            }
            handler.tls_config = Some(Arc::new(config));
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
                    .into_iter()
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

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

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
            sess.effective_destination()?.host()
        };
        if let Some(stream) = stream {
            #[cfg(feature = "rustls-tls")]
            if let Some(tls_config) = self.tls_config.as_ref() {
                trace!("handling TLS {} with rustls", &name);
                let connector = TlsConnector::from(tls_config.clone());
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
