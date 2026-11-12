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
///
/// With `ech_config_list` (a serialized ECHConfigList) the handshake uses
/// Encrypted Client Hello: `name` goes in the encrypted inner ClientHello,
/// the outer one carries the config's public name. It fails closed, as the
/// rustls backend: a list without a usable config fails before anything is
/// sent; a server that rejects ECH (stale config, no ECH) fails the
/// handshake (BoringSSL's `SSL_R_ECH_REJECTED`, after checking the
/// certificate against the public name), its retry configs are not used for
/// a second attempt (rustls returns them in the error, leaf does not retry
/// either); a handshake that ends without ECH is an error.
pub async fn connect<S>(
    connector: &SslConnector,
    name: &str,
    insecure: bool,
    ech_config_list: Option<&[u8]>,
    stream: S,
) -> io::Result<SslStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut config = connector
        .configure()
        .map_err(|e| io::Error::other(format!("new ssl failed: {}", e)))?
        .verify_hostname(!insecure);
    if let Some(list) = ech_config_list {
        set_ech_config_list(&mut config, list)?;
    }
    let stream = tokio_boring::connect(config, name, stream)
        .await
        .map_err(|e| {
            let rejected = ech_config_list.is_some()
                && e.ssl().is_some_and(|ssl| {
                    !ssl.ech_accepted() && ssl.get_ech_name_override().is_some()
                });
            let msg = if rejected {
                let retry = e
                    .ssl()
                    .is_some_and(|ssl| ssl.get_ech_retry_configs().is_some());
                format!(
                    "connect tls failed: ech rejected by the server ({}): {}",
                    if retry {
                        "it sent retry configs, not used"
                    } else {
                        "no retry configs"
                    },
                    e
                )
            } else {
                format!("connect tls failed: {}", e)
            };
            io::Error::new(io::ErrorKind::InvalidInput, msg)
        })?;
    if ech_config_list.is_some() && !stream.ssl().ech_accepted() {
        // Not expected: BoringSSL fails a rejected ECH handshake itself.
        return Err(io::Error::other("connect tls failed: ech not accepted"));
    }
    Ok(stream)
}

/// Offers ECH with `list` on `ssl`, refusing a malformed list, and (unlike
/// BoringSSL's default) failing the handshake instead of sending a plain
/// ClientHello when the list has no config BoringSSL supports.
fn set_ech_config_list(ssl: &mut boring::ssl::SslRef, list: &[u8]) -> io::Result<()> {
    use foreign_types::ForeignTypeRef;
    ssl.set_ech_config_list(list).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid ech config list: {}", e),
        )
    })?;
    // `boring` does not wrap it. Safe: `ssl` is a live `SSL` we hold
    // exclusively, the call only sets a flag on it.
    unsafe { boring_sys::SSL_set_reject_unusable_ech_config(ssl.as_ptr(), 1) };
    Ok(())
}

/// Checks that BoringSSL parses `list` as an ECHConfigList (as a connection
/// would), so a bad fixed config fails the config load.
pub fn check_ech_config_list(connector: &SslConnector, list: &[u8]) -> Result<()> {
    let mut ssl = boring::ssl::Ssl::new(connector.context())?;
    set_ech_config_list(&mut ssl, list).map_err(|e| anyhow!("{}", e))
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

    use boring::hpke::HpkeKey;
    use boring::ssl::{select_next_proto, AlpnError, NameType, SslEchKeys};
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
        pub ech_accepted: bool,
    }

    /// A TLS server written directly against BoringSSL (not leaf's inbound):
    /// it offers `h2` and `http/1.1`, accepts one connection, reports SNI and
    /// ALPN (None if the handshake failed) and echoes 5 bytes.
    pub(crate) async fn server(pki: &Pki) -> (SocketAddr, oneshot::Receiver<Option<Seen>>) {
        server_with_ech(pki, &[]).await
    }

    /// [`server`] with ECH keys (none: no ECH).
    pub(crate) async fn server_with_ech(
        pki: &Pki,
        ech: &[&EchKey],
    ) -> (SocketAddr, oneshot::Receiver<Option<Seen>>) {
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
        if !ech.is_empty() {
            let mut keys = SslEchKeys::builder().unwrap();
            for k in ech {
                keys.add_key(true, &k.config, k.hpke_key()).unwrap();
            }
            builder.set_ech_keys(&keys.build()).unwrap();
        }
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
                        ech_accepted: tls.ssl().ech_accepted(),
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

    /// A fresh ECH key (X25519, BoringSSL's HPKE) and its ECHConfig, made
    /// by BoringSSL (`boring` wraps neither call). Test-only.
    pub(crate) struct EchKey {
        /// One serialized ECHConfig.
        pub config: Vec<u8>,
        private: Vec<u8>,
    }

    impl EchKey {
        pub(crate) fn new(config_id: u8, public_name: &str) -> EchKey {
            let name = std::ffi::CString::new(public_name).unwrap();
            // Safe: every pointer is checked, freed once, and the buffers
            // are sized as the calls require.
            unsafe {
                let key = boring_sys::EVP_HPKE_KEY_new();
                assert!(!key.is_null());
                assert_eq!(
                    boring_sys::EVP_HPKE_KEY_generate(
                        key,
                        boring_sys::EVP_hpke_x25519_hkdf_sha256()
                    ),
                    1
                );
                let mut private = vec![0u8; boring_sys::EVP_HPKE_MAX_PRIVATE_KEY_LENGTH as usize];
                let mut len = 0usize;
                assert_eq!(
                    boring_sys::EVP_HPKE_KEY_private_key(
                        key,
                        private.as_mut_ptr(),
                        &mut len,
                        private.len()
                    ),
                    1
                );
                private.truncate(len);
                let mut out: *mut u8 = std::ptr::null_mut();
                let mut out_len = 0usize;
                let ok = boring_sys::SSL_marshal_ech_config(
                    &mut out,
                    &mut out_len,
                    config_id,
                    key,
                    name.as_ptr(),
                    0,
                );
                boring_sys::EVP_HPKE_KEY_free(key);
                assert_eq!(ok, 1);
                let config = std::slice::from_raw_parts(out, out_len).to_vec();
                boring_sys::OPENSSL_free(out.cast());
                EchKey { config, private }
            }
        }

        fn hpke_key(&self) -> HpkeKey {
            // `dhkem_p256_sha256` is boring's misnomer: it is X25519.
            HpkeKey::dhkem_p256_sha256(&self.private).unwrap()
        }

        /// An ECHConfigList with this config alone.
        pub(crate) fn list(&self) -> Vec<u8> {
            let mut list = (self.config.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&self.config);
            list
        }
    }

    /// A TCP relay to `to` for one connection; yields what the client sent
    /// (for looking at the ClientHello on the wire).
    pub(crate) async fn recording_relay(
        to: SocketAddr,
    ) -> (SocketAddr, oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let server = TcpStream::connect(to).await.unwrap();
            let (mut cr, mut cw) = client.into_split();
            let (mut sr, mut sw) = server.into_split();
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut sr, &mut cw).await;
            });
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match cr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        seen.extend_from_slice(&buf[..n]);
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = sw.shutdown().await;
            let _ = tx.send(seen);
        });
        (addr, rx)
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    /// ECH accepted: the server sees the inner name and accepts ECH, the
    /// ClientHello on the wire carries the public name and not the inner one.
    #[tokio::test]
    async fn ech_hides_the_server_name_behind_the_public_name() {
        let pki = pki(&["secret.example", "public.example"]);
        let ech = EchKey::new(7, "public.example");
        let (addr, seen) = server_with_ech(&pki, &[&ech]).await;
        let (relay, wire) = recording_relay(addr).await;
        let connector = connector(&[], Some(&pki.ca_pem), false).unwrap();
        let tcp = TcpStream::connect(relay).await.unwrap();
        let mut tls = connect(&connector, "secret.example", false, Some(&ech.list()), tcp)
            .await
            .unwrap();
        assert!(tls.ssl().ech_accepted());
        ping(&mut tls).await;
        let _ = tls.shutdown().await;
        drop(tls);
        let seen = seen.await.unwrap().unwrap();
        assert!(seen.ech_accepted, "server accepted ECH");
        assert_eq!(seen.sni.as_deref(), Some("secret.example"), "inner SNI");
        let wire = wire.await.unwrap();
        assert!(
            contains(&wire, "public.example"),
            "outer SNI is the public name"
        );
        assert!(
            !contains(&wire, "secret.example"),
            "inner name not in the clear"
        );

        // Without ECH the name is in the clear (the check above can fail).
        let (addr, _seen) = server(&pki).await;
        let (relay, wire) = recording_relay(addr).await;
        let tcp = TcpStream::connect(relay).await.unwrap();
        let mut tls = connect(&connector, "secret.example", false, None, tcp)
            .await
            .unwrap();
        ping(&mut tls).await;
        drop(tls);
        assert!(contains(&wire.await.unwrap(), "secret.example"));
    }

    /// A stale config (the server has another key) and a server without ECH
    /// are rejected: the handshake fails, whether or not the server sent
    /// retry configs, as the rustls backend's. The certificate covers the
    /// public name, so BoringSSL gets as far as `ECH_REJECTED`.
    #[tokio::test]
    async fn ech_rejection_fails_closed() {
        let pki = pki(&["secret.example", "public.example"]);
        let stale = EchKey::new(1, "public.example");
        let current = EchKey::new(2, "public.example");
        let connector = connector(&[], Some(&pki.ca_pem), false).unwrap();

        let (addr, seen) = server_with_ech(&pki, &[&current]).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect(
            &connector,
            "secret.example",
            false,
            Some(&stale.list()),
            tcp,
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ech rejected"), "{msg}");
        assert!(msg.contains("retry configs, not used"), "{msg}");
        assert!(msg.contains("ECH_REJECTED"), "{msg}");
        // The server completed the outer handshake (public name), unused.
        if let Some(seen) = seen.await.unwrap() {
            assert!(!seen.ech_accepted);
            assert_eq!(seen.sni.as_deref(), Some("public.example"));
        }

        let (addr, _seen) = server(&pki).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect(
            &connector,
            "secret.example",
            false,
            Some(&stale.list()),
            tcp,
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ech rejected") && msg.contains("no retry configs"),
            "{msg}"
        );
    }

    /// A list BoringSSL cannot use (unknown KEM) fails before anything is
    /// sent, instead of BoringSSL's default of a plain ClientHello; a
    /// malformed one is refused.
    #[tokio::test]
    async fn unusable_or_malformed_ech_config_lists_are_refused() {
        let pki = pki(&["secret.example", "public.example"]);
        let ech = EchKey::new(3, "public.example");
        let mut unusable = ech.list();
        // list length (2), version (2), length (2), config_id (1), kem_id (2).
        unusable[7..9].copy_from_slice(&0xfefeu16.to_be_bytes());
        let connector = connector(&[], Some(&pki.ca_pem), false).unwrap();
        let (addr, _seen) = server_with_ech(&pki, &[&ech]).await;
        let (relay, wire) = recording_relay(addr).await;
        let tcp = TcpStream::connect(relay).await.unwrap();
        assert!(
            connect(&connector, "secret.example", false, Some(&unusable), tcp)
                .await
                .is_err()
        );
        assert!(wire.await.unwrap().is_empty(), "nothing was sent");

        check_ech_config_list(&connector, &ech.list()).unwrap();
        assert!(check_ech_config_list(&connector, &[0, 3, 1, 2, 3]).is_err());
        let (addr, _seen) = server_with_ech(&pki, &[&ech]).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect(&connector, "secret.example", false, Some(&[0, 1, 9]), tcp)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid ech config list"), "{err}");
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
        let mut tls = connect(&connector, "localhost", false, None, tcp)
            .await
            .unwrap();
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
        let mut tls = connect(&connector, "127.0.0.1", false, None, tcp)
            .await
            .unwrap();
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
        let err = connect(&wrong, "localhost", false, None, tcp)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("connect tls failed"), "{}", err);
        assert!(seen.await.unwrap().is_none());

        // The right CA, another name.
        let (addr, seen) = server(&pki).await;
        let right = connector(&[], Some(&pki.ca_pem), false).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        assert!(connect(&right, "other.example", false, None, tcp)
            .await
            .is_err());
        assert!(seen.await.unwrap().is_none());

        // insecure: neither is checked.
        let (addr, seen) = server(&pki).await;
        let insecure = connector(&[], Some(&other.ca_pem), true).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect(&insecure, "other.example", true, None, tcp)
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

        // Inbound ECH is refused, as with the openssl backend (no backend
        // has server ECH).
        assert!(inbound::StreamHandler::new(
            pki.chain_pem.clone(),
            pki.key_pem.clone(),
            Some("AQID".to_string()),
            Some("AQID".to_string()),
        )
        .is_err());
    }

    /// leaf's TLS outbound with `ech` and a fixed config (base64, as in a
    /// conf's `tls-ech-config-list`; DNS lookup off): the server sees the
    /// inner name over ECH. A bad fixed config fails `new`, as with rustls.
    #[cfg(all(feature = "outbound-tls", feature = "base64"))]
    #[tokio::test]
    async fn leaf_outbound_with_a_fixed_ech_config() {
        use base64::Engine;

        use crate::proxy::tls::outbound;
        use crate::proxy::OutboundStreamHandler;
        use crate::session::Session;

        let pki = pki(&["secret.example", "public.example"]);
        let ech = EchKey::new(9, "public.example");
        let b64 = base64::engine::general_purpose::STANDARD.encode(ech.list());
        let handler = |list: Option<String>, disable_dns: bool| {
            outbound::StreamHandler::new(
                "secret.example".to_string(),
                vec![],
                Some(pki.ca_pem.clone()),
                None,
                false,
                true,
                disable_dns,
                list,
                test_dns_client(),
            )
        };
        // Also a single ECHConfig (no list length), as rustls takes it.
        let single = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&ech.config);
        for list in [b64.clone(), single] {
            let client = handler(Some(list), true).unwrap();
            let (addr, seen) = server_with_ech(&pki, &[&ech]).await;
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut stream = client
                .handle(&Session::default(), None, Some(Box::new(tcp)))
                .await
                .unwrap();
            ping(&mut stream).await;
            let seen = seen.await.unwrap().unwrap();
            assert!(seen.ech_accepted);
            assert_eq!(seen.sni.as_deref(), Some("secret.example"));
        }
        // A stale fixed config: refused, not sent in the clear.
        let other = EchKey::new(9, "public.example");
        let client = handler(Some(b64), true).unwrap();
        let (addr, _seen) = server_with_ech(&pki, &[&other]).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = client
            .handle(&Session::default(), None, Some(Box::new(tcp)))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("ech rejected"), "{}", err);
        // Bad fixed configs fail at load.
        assert!(handler(Some("$$$".to_string()), true).is_err());
        assert!(handler(Some("AQID".to_string()), true).is_err());
        // ECH on with DNS lookup off and no fixed config: a plain handshake,
        // as in the rustls backend (nothing to encrypt to).
        let client = handler(None, true).unwrap();
        let (addr, seen) = server(&pki).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = client
            .handle(&Session::default(), None, Some(Box::new(tcp)))
            .await
            .unwrap();
        ping(&mut stream).await;
        assert!(!seen.await.unwrap().unwrap().ech_accepted);
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
