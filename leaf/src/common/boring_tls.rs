//! BoringSSL TLS backend (feature `boring-tls`), shared by the TLS outbound,
//! the TLS inbound and the DNS-over-HTTPS client.
//!
//! It uses the `boring` / `tokio-boring` crates, the same ones kiri uses, so a
//! leaf built with `default-boring` and `kiri` links a single BoringSSL.

use std::io;
use std::sync::Once;

use anyhow::{anyhow, Result};
use boring::{
    pkey::PKey,
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring::SslStream;

/// Lets BoringSSL find the system CA bundle the way the OpenSSL backend does:
/// `SSL_CERT_FILE` / `SSL_CERT_DIR` set by the host (e.g. an iOS app pointing
/// it at the `cacert.pem` it ships) win; otherwise `openssl-probe` points them
/// at a bundle in a well-known location if there is one. BoringSSL reads them
/// when a connector is built (`SSL_CTX_set_default_verify_paths`).
fn init_system_roots() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe { openssl_probe::init_openssl_env_vars() });
}

/// PEM data given inline (contains `-----BEGIN`) or as a file path, as the
/// rustls backend accepts it.
fn read_pem(value: &str) -> io::Result<Vec<u8>> {
    if value.contains("-----BEGIN") {
        Ok(value.as_bytes().to_vec())
    } else {
        std::fs::read(value)
    }
}

fn load_certs(certificate: &str) -> Result<Vec<X509>> {
    let pem = read_pem(certificate)
        .map_err(|e| anyhow!("load certificates from {} failed: {}", certificate, e))?;
    let certs = X509::stack_from_pem(&pem)
        .map_err(|e| anyhow!("load certificates from {} failed: {}", certificate, e))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates in {}", certificate));
    }
    Ok(certs)
}

/// A client context. `certificate` (PEM, inline or a path) replaces the
/// system roots as trust anchors, as in the rustls backend; `insecure` skips
/// certificate verification.
pub fn connector(
    alpns: &[String],
    certificate: Option<&str>,
    insecure: bool,
) -> Result<SslConnector> {
    init_system_roots();
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| anyhow!("create ssl connector failed: {}", e))?;
    if let Some(certificate) = certificate {
        let mut store = X509StoreBuilder::new()?;
        for cert in load_certs(certificate)? {
            store.add_cert(cert)?;
        }
        builder.set_cert_store(store.build());
    }
    if !alpns.is_empty() {
        let mut wire = Vec::new();
        for alpn in alpns {
            let len = u8::try_from(alpn.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| anyhow!("invalid alpn {:?}", alpn))?;
            wire.push(len);
            wire.extend_from_slice(alpn.as_bytes());
        }
        builder
            .set_alpn_protos(&wire)
            .map_err(|e| anyhow!("set alpn failed: {}", e))?;
    }
    if insecure {
        builder.set_verify(SslVerifyMode::NONE);
    }
    Ok(builder.build())
}

/// Client handshake. `name` is the SNI (unless it is an IP address) and the
/// name the certificate must match (host name or IP address).
pub async fn connect<S>(
    connector: &SslConnector,
    name: &str,
    insecure: bool,
    stream: S,
) -> io::Result<SslStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = connector
        .configure()
        .map_err(|e| io::Error::other(format!("new ssl failed: {}", e)))?
        .verify_hostname(!insecure);
    tokio_boring::connect(config, name, stream)
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("connect tls failed: {}", e),
            )
        })
}

/// A server context from a PEM certificate chain (leaf first) and a PEM
/// private key (PKCS#8, PKCS#1 RSA or SEC1 EC), each inline or a path.
pub fn acceptor(certificate: &str, certificate_key: &str) -> Result<SslAcceptor> {
    let mut certs = load_certs(certificate)?.into_iter();
    let key_pem = read_pem(certificate_key)
        .map_err(|e| anyhow!("load keys from {} failed: {}", certificate_key, e))?;
    let key = PKey::private_key_from_pem(&key_pem)
        .map_err(|e| anyhow!("load keys from {} failed: {}", certificate_key, e))?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| anyhow!("create ssl acceptor failed: {}", e))?;
    if let Some(leaf) = certs.next() {
        builder.set_certificate(&leaf)?;
    }
    for cert in certs {
        builder.add_extra_chain_cert(cert)?;
    }
    builder
        .set_private_key(&key)
        .and_then(|_| builder.check_private_key())
        .map_err(|e| anyhow!("certificate and key do not match: {}", e))?;
    Ok(builder.build())
}

/// Server handshake.
pub async fn accept<S>(acceptor: &SslAcceptor, stream: S) -> io::Result<SslStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio_boring::accept(acceptor, stream)
        .await
        .map_err(|e| io::Error::other(format!("accept tls failed: {}", e)))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::SocketAddr;

    use boring::ssl::{select_next_proto, AlpnError, NameType};
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    use super::*;

    /// A test CA, an intermediate and a server certificate for `names`
    /// (host names or IP addresses), as public servers are set up.
    pub(crate) struct Pki {
        pub ca_pem: String,
        /// Server certificate, then the intermediate.
        pub chain_pem: String,
        /// PKCS#8.
        pub key_pem: String,
    }

    pub(crate) fn pki(names: &[&str]) -> Pki {
        fn params(cn: &str, names: &[&str], ca: bool) -> CertificateParams {
            let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
            let mut params = CertificateParams::new(names).unwrap();
            params.distinguished_name = DistinguishedName::new();
            params.distinguished_name.push(DnType::CommonName, cn);
            if ca {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            }
            params
        }
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = params("leaf test root", &[], true)
            .self_signed(&ca_key)
            .unwrap();
        let int_key = KeyPair::generate().unwrap();
        let int_cert = params("leaf test intermediate", &[], true)
            .signed_by(&int_key, &ca_cert, &ca_key)
            .unwrap();
        let key = KeyPair::generate().unwrap();
        let cert = params(names[0], names, false)
            .signed_by(&key, &int_cert, &int_key)
            .unwrap();
        Pki {
            ca_pem: ca_cert.pem(),
            chain_pem: format!("{}{}", cert.pem(), int_cert.pem()),
            key_pem: key.serialize_pem(),
        }
    }

    /// What a server saw of one connection.
    #[derive(Debug)]
    pub(crate) struct Seen {
        pub sni: Option<String>,
        pub alpn: Option<Vec<u8>>,
    }

    /// A TLS server written directly against BoringSSL (not leaf's inbound):
    /// it offers `h2` and `http/1.1`, accepts one connection, reports SNI and
    /// ALPN (None if the handshake failed) and echoes 5 bytes.
    pub(crate) async fn server(pki: &Pki) -> (SocketAddr, oneshot::Receiver<Option<Seen>>) {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        let mut certs = X509::stack_from_pem(pki.chain_pem.as_bytes())
            .unwrap()
            .into_iter();
        builder.set_certificate(&certs.next().unwrap()).unwrap();
        for cert in certs {
            builder.add_extra_chain_cert(cert).unwrap();
        }
        builder
            .set_private_key(&PKey::private_key_from_pem(pki.key_pem.as_bytes()).unwrap())
            .unwrap();
        builder.set_alpn_select_callback(|_, client| {
            select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(AlpnError::NOACK)
        });
        let acceptor = builder.build();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            match tokio_boring::accept(&acceptor, tcp).await {
                Ok(mut tls) => {
                    let seen = Seen {
                        sni: tls
                            .ssl()
                            .servername(NameType::HOST_NAME)
                            .map(str::to_string),
                        alpn: tls.ssl().selected_alpn_protocol().map(<[u8]>::to_vec),
                    };
                    let _ = tx.send(Some(seen));
                    let mut buf = [0u8; 5];
                    if tls.read_exact(&mut buf).await.is_ok() {
                        let _ = tls.write_all(&buf).await;
                        let _ = tls.shutdown().await;
                    }
                }
                Err(_) => {
                    let _ = tx.send(None);
                }
            }
        });
        (addr, rx)
    }

    pub(crate) async fn ping<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn connect_verifies_against_the_given_ca_with_sni_and_alpn() {
        let pki = pki(&["localhost"]);
        let (addr, seen) = server(&pki).await;
        let alpns = vec!["h2".to_string(), "http/1.1".to_string()];
        let connector = connector(&alpns, Some(&pki.ca_pem), false).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect(&connector, "localhost", false, tcp).await.unwrap();
        assert_eq!(tls.ssl().selected_alpn_protocol(), Some(&b"h2"[..]));
        ping(&mut tls).await;
        let seen = seen.await.unwrap().unwrap();
        assert_eq!(seen.sni.as_deref(), Some("localhost"));
        assert_eq!(seen.alpn.as_deref(), Some(&b"h2"[..]));
    }

    #[tokio::test]
    async fn ca_from_a_file_and_an_ip_address_name_without_sni() {
        let pki = pki(&["127.0.0.1"]);
        let dir = std::env::temp_dir().join(format!("leaf-boring-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_path = dir.join("ca.pem");
        std::fs::write(&ca_path, &pki.ca_pem).unwrap();
        let (addr, seen) = server(&pki).await;
        let connector = connector(&[], Some(ca_path.to_str().unwrap()), false).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect(&connector, "127.0.0.1", false, tcp).await.unwrap();
        ping(&mut tls).await;
        let seen = seen.await.unwrap().unwrap();
        assert_eq!(seen.sni, None, "no SNI for an IP address");
        assert_eq!(seen.alpn, None, "no ALPN unless configured");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn wrong_ca_or_name_is_refused_unless_insecure() {
        let pki = pki(&["localhost"]);
        let other = super::tests::pki(&["localhost"]);

        // Trusting another CA.
        let (addr, seen) = server(&pki).await;
        let wrong = connector(&[], Some(&other.ca_pem), false).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect(&wrong, "localhost", false, tcp).await.unwrap_err();
        assert!(err.to_string().contains("connect tls failed"), "{}", err);
        assert!(seen.await.unwrap().is_none());

        // The right CA, another name.
        let (addr, seen) = server(&pki).await;
        let right = connector(&[], Some(&pki.ca_pem), false).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        assert!(connect(&right, "other.example", false, tcp).await.is_err());
        assert!(seen.await.unwrap().is_none());

        // insecure: neither is checked.
        let (addr, seen) = server(&pki).await;
        let insecure = connector(&[], Some(&other.ca_pem), true).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect(&insecure, "other.example", true, tcp)
            .await
            .unwrap();
        ping(&mut tls).await;
        assert!(seen.await.unwrap().is_some());
    }

    #[test]
    fn bad_inputs_are_refused() {
        let pki = pki(&["localhost"]);
        assert!(connector(&[], Some("/nonexistent/ca.pem"), false).is_err());
        assert!(connector(
            &[],
            Some("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
            false
        )
        .is_err());
        assert!(connector(&["".to_string()], None, false).is_err());
        assert!(connector(&["x".repeat(256)], None, false).is_err());
        let other = super::tests::pki(&["localhost"]);
        let err = acceptor(&pki.chain_pem, &other.key_pem).err().unwrap();
        assert!(err.to_string().contains("do not match"), "{}", err);
        assert!(acceptor("/nonexistent/cert.pem", &pki.key_pem).is_err());
    }

    /// leaf's TLS outbound against leaf's TLS inbound, both on BoringSSL,
    /// with a PKCS#8 and a SEC1 (`EC PRIVATE KEY`) key.
    #[cfg(all(feature = "inbound-tls", feature = "outbound-tls"))]
    #[tokio::test]
    async fn leaf_outbound_to_leaf_inbound() {
        use crate::proxy::tls::{inbound, outbound};
        use crate::proxy::{InboundStreamHandler, InboundTransport, OutboundStreamHandler};
        use crate::session::Session;

        let pki = pki(&["localhost"]);
        let sec1 = String::from_utf8(
            PKey::private_key_from_pem(pki.key_pem.as_bytes())
                .unwrap()
                .ec_key()
                .unwrap()
                .private_key_to_pem()
                .unwrap(),
        )
        .unwrap();
        assert!(sec1.contains("BEGIN EC PRIVATE KEY"));
        for key in [pki.key_pem.clone(), sec1] {
            let server =
                inbound::StreamHandler::new(pki.chain_pem.clone(), key, None, None).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let transport = server
                    .handle(Session::default(), Box::new(tcp))
                    .await
                    .unwrap();
                let InboundTransport::Stream(mut stream, _) = transport else {
                    panic!("not a stream");
                };
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.unwrap();
                stream.write_all(&buf).await.unwrap();
            });

            let client = outbound::StreamHandler::new(
                "localhost".to_string(),
                vec!["http/1.1".to_string()],
                Some(pki.ca_pem.clone()),
                None,
                false,
                false,
                false,
                None,
                test_dns_client(),
            )
            .unwrap();
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut stream = client
                .handle(&Session::default(), None, Some(Box::new(tcp)))
                .await
                .unwrap();
            ping(&mut stream).await;
        }

        // ECH is refused, as with the openssl backend.
        assert!(inbound::StreamHandler::new(
            pki.chain_pem.clone(),
            pki.key_pem.clone(),
            Some("AQID".to_string()),
            Some("AQID".to_string()),
        )
        .is_err());
        let client = outbound::StreamHandler::new(
            "localhost".to_string(),
            vec![],
            Some(pki.ca_pem.clone()),
            None,
            false,
            true,
            false,
            None,
            test_dns_client(),
        )
        .unwrap();
        let (addr, _seen) = server(&pki).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = client
            .handle(&Session::default(), None, Some(Box::new(tcp)))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("ech is not supported"), "{}", err);
    }

    pub(crate) fn test_dns_client() -> crate::app::SyncDnsClient {
        let mut dns = crate::config::Dns::new();
        dns.servers.push("1.1.1.1".to_string());
        let dns = protobuf::MessageField::some(dns);
        std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::app::dns::DnsClient::new(&dns).unwrap(),
        ))
    }
}
