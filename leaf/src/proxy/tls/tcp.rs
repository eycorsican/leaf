use std::io;

use async_trait::async_trait;
use futures::TryFutureExt;
use log::*;

#[cfg(feature = "rustls-tls")]
use {
    std::sync::Arc,
    tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector},
};

#[cfg(feature = "openssl-tls")]
use {
    openssl::ssl::{Ssl, SslConnector, SslMethod},
    std::pin::Pin,
    std::sync::Once,
    tokio_openssl::SslStream,
};

use crate::{
    proxy::{OutboundConnect, ProxyStream, SimpleProxyStream, TcpOutboundHandler},
    session::Session,
};

pub struct Handler {
    server_name: String,
    #[cfg(feature = "rustls-tls")]
    tls_config: Arc<ClientConfig>,
    #[cfg(feature = "openssl-tls")]
    ssl_connector: SslConnector,
}

impl Handler {
    pub fn new(server_name: String, alpns: Vec<String>) -> Self {
        #[cfg(feature = "rustls-tls")]
        {
            let mut config = ClientConfig::new();
            config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

            for alpn in alpns {
                config.alpn_protocols.push(alpn.as_bytes().to_vec());
            }
            Handler {
                server_name,
                tls_config: Arc::new(config),
            }
        }
        #[cfg(feature = "openssl-tls")]
        {
            {
                static ONCE: Once = Once::new();
                ONCE.call_once(openssl_probe::init_ssl_cert_env_vars);
            }
            let mut builder =
                SslConnector::builder(SslMethod::tls()).expect("create ssl connector failed");
            if alpns.len() > 0 {
                let wire = alpns
                    .into_iter()
                    .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
                    .collect::<Vec<Vec<u8>>>()
                    .concat();
                builder.set_alpn_protos(&wire).expect("set alpn failed");
            }
            let ssl_connector = builder.build();
            Handler {
                server_name,
                ssl_connector,
            }
        }
    }
}

fn tls_err<E>(_error: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, "tls error")
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        // TODO optimize, dont need copy
        let name = if !&self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        trace!("wrapping tls with name {}", &name);
        if let Some(stream) = stream {
            #[cfg(feature = "rustls-tls")]
            {
                let config = TlsConnector::from(self.tls_config.clone());
                let dnsname = DNSNameRef::try_from_ascii_str(&name).map_err(tls_err)?;
                let tls_stream = config.connect(dnsname, stream).map_err(tls_err).await?;
                // FIXME check negotiated alpn
                Ok(Box::new(SimpleProxyStream(tls_stream)))
            }
            #[cfg(feature = "openssl-tls")]
            {
                let mut ssl = Ssl::new(self.ssl_connector.context()).map_err(tls_err)?;
                ssl.set_hostname(&name).map_err(tls_err)?;
                let mut stream = SslStream::new(ssl, stream).map_err(tls_err)?;
                Pin::new(&mut stream)
                    .connect()
                    .map_err(|e| {
                        log::trace!("connect tls stream failed: {}", e);
                        tls_err(e)
                    })
                    .await?;
                Ok(Box::new(SimpleProxyStream(stream)))
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid tls input"))
        }
    }
}
