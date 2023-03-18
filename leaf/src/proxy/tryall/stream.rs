use std::io;

use async_trait::async_trait;
use futures::future::select_ok;

use crate::{app::SyncDnsClient, proxy::*, session::Session};

struct HandleResult {
    idx: usize,
    stream: AnyStream,
}

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub delay_base: u32,
    pub dns_client: SyncDnsClient,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let mut tasks = Vec::new();
        for (i, a) in self.actors.iter().enumerate() {
            let t = async move {
                if self.delay_base > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        (self.delay_base * i as u32) as u64,
                    ))
                    .await;
                }
                let stream =
                    crate::proxy::connect_stream_outbound(sess, self.dns_client.clone(), a).await?;
                a.stream()?
                    .handle(sess, stream)
                    .await
                    .map(|stream| HandleResult { idx: i, stream })
            };
            tasks.push(Box::pin(t));
        }
        match select_ok(tasks.into_iter()).await {
            Ok(v) => {
                debug!(
                    "tryall handles [{}:{}] to [{}]",
                    sess.network,
                    sess.destination,
                    self.actors[v.0.idx].tag()
                );
                Ok(v.0.stream)
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("all outbound attempts failed, last error: {}", e),
            )),
        }
    }
}
