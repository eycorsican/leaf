use async_trait::async_trait;

use crate::app::fake_dns::FakeDns;
use crate::{proxy::*, session::Session};

use super::NfManager;

pub struct Handler {
    pub manager: Arc<NfManager>,
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let (remote_addr, process_name) =
            if let Some(info) = super::TCP_INFO.lock().unwrap().remove(&sess.source.port()) {
                (info.remote_addr, info.process_name)
            } else {
                return Err(std::io::Error::other(format!(
                    "tcp conn not found, source={} ",
                    &sess.source
                )));
            };

        sess.destination = crate::session::SocksAddr::from(remote_addr);
        sess.process_name = process_name;

        let remote_ip = remote_addr.ip();
        if self.manager.fake_dns.is_fake_ip(&remote_ip).await {
            if let Some(domain) = self.manager.fake_dns.query_domain(&remote_ip).await {
                sess.destination = SocksAddr::Domain(domain, remote_addr.port());
            } else {
                if remote_addr.port() != 443 && remote_addr.port() != 80 {
                    return Err(std::io::Error::other(format!(
                        "paired domain not found, addr={}",
                        &remote_addr.ip()
                    )));
                }
            }
        }

        Ok(InboundTransport::Stream(stream, sess))
    }
}
