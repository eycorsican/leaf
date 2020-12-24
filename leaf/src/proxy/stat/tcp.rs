use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{io, net::SocketAddr, pin::Pin, sync::Arc};

use async_trait::async_trait;
use futures::{
    future::BoxFuture,
    ready,
    task::{Context, Poll},
    Future,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, channel, Sender};
use tokio::sync::Mutex as TokioMutex;
use warp::Filter;

use crate::{
    proxy::{OutboundConnect, ProxyStream, TcpOutboundHandler},
    session::{Session, SocksAddr},
};

pub struct StatProxyStream<T>(
    pub T,
    pub Arc<AtomicUsize>,
    pub Arc<AtomicUsize>,
    pub mpsc::Sender<usize>,
);

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> ProxyStream for StatProxyStream<T> {}

impl<T: AsyncRead + Unpin> AsyncRead for StatProxyStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let key = me as *const _ as usize;
        let n = ready!(AsyncRead::poll_read(Pin::new(&mut me.0), cx, buf))?;
        me.2.fetch_add(n, Ordering::SeqCst);
        Poll::Ready(Ok(n))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for StatProxyStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let key = me as *const _ as usize;
        let n = ready!(AsyncWrite::poll_write(Pin::new(&mut me.0), cx, buf))?;
        me.1.fetch_add(n, Ordering::SeqCst);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let key = me as *const _ as usize;
        // FIXME remove sess after shutdown?
        let mut send_fut = Box::pin(me.3.send(key));
        send_fut.as_mut().poll(cx);
        AsyncWrite::poll_shutdown(Pin::new(&mut me.0), cx)
    }
}

struct SessionStat {
    pub upload_bytes: Arc<AtomicUsize>,
    pub download_bytes: Arc<AtomicUsize>,
    pub inbound_tag: String,
    pub destination: SocksAddr,
}

impl SessionStat {
    fn new(
        upload_counter: Arc<AtomicUsize>,
        download_counter: Arc<AtomicUsize>,
        inbound_tag: String,
        destination: SocksAddr,
    ) -> Self {
        SessionStat {
            upload_bytes: upload_counter,
            download_bytes: download_counter,
            inbound_tag,
            destination,
        }
    }
}

use std::convert::Infallible;

type SessionMap = Arc<TokioMutex<HashMap<usize, SessionStat>>>;

fn with_sessions(
    sessions: SessionMap,
) -> impl Filter<Extract = (SessionMap,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || sessions.clone())
}

async fn summarize_sessions(sessions: SessionMap) -> Result<impl warp::Reply, Infallible> {
    let mut resp = "".to_string();
    resp.push_str("<html>");
    resp.push_str(
        "<head><style>
table, th, td {
  border: 1px solid black;
  border-collapse: collapse;
  text-align: right;
  padding: 4;
  font-size: small;
}

.highlight {
  font-weight: bold;
}
</style></head>",
    );
    resp.push_str("<table style=\"border=4px solid\">");
    resp.push_str("<tr><td>Remote Addr</td><td>Upload Bytes</td><td>Download Bytes</td></tr>");
    for (key, val) in sessions.lock().await.iter() {
        resp.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            &val.destination.to_string(),
            &val.upload_bytes.load(Ordering::Relaxed),
            &val.download_bytes.load(Ordering::Relaxed)
        ));
    }
    resp.push_str("</table>");
    resp.push_str("</html>");
    Ok(warp::reply::html(resp))
}

pub struct Handler {
    sessions: Arc<TokioMutex<HashMap<usize, SessionStat>>>,
    tx: mpsc::Sender<usize>,
    task: TokioMutex<Option<BoxFuture<'static, ()>>>,
    task2: TokioMutex<Option<BoxFuture<'static, ()>>>,
}

impl Handler {
    pub fn new(address: String, port: u16) -> Self {
        let sessions = Arc::new(TokioMutex::new(HashMap::<usize, SessionStat>::new()));
        let (tx, mut rx) = mpsc::channel(100);

        let sessions2 = sessions.clone();
        let stat_service = warp::path("stat")
            .and(with_sessions(sessions2))
            .and_then(summarize_sessions);

        let stat_addr = format!("{}:{}", address, port)
            .parse::<SocketAddr>()
            .unwrap();
        let task2: BoxFuture<'static, ()> = Box::pin(async move {
            warp::serve(stat_service).run(stat_addr).await;
        });

        let sessions2 = sessions.clone();
        let task: BoxFuture<'static, ()> = Box::pin(async move {
            while let Some(key) = rx.recv().await {
                sessions2.lock().await.remove(&key);
                for (key, val) in sessions2.lock().await.iter() {
                    log::debug!(
                        "{}: [{}] {} ({}) ({})",
                        key,
                        &val.inbound_tag,
                        &val.destination.to_string(),
                        &val.upload_bytes.load(Ordering::Relaxed),
                        &val.download_bytes.load(Ordering::Relaxed)
                    );
                }
            }
        });

        Handler {
            sessions,
            tx,
            task: TokioMutex::new(Some(task)),
            task2: TokioMutex::new(Some(task2)),
        }
    }
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        if self.task.lock().await.is_some() {
            if let Some(task) = self.task.lock().await.take() {
                tokio::spawn(task);
            }
        }

        if self.task2.lock().await.is_some() {
            if let Some(task) = self.task2.lock().await.take() {
                tokio::spawn(task);
            }
        }

        match stream {
            Some(stream) => {
                let upload_counter = Arc::new(AtomicUsize::new(0));
                let download_counter = Arc::new(AtomicUsize::new(0));
                let stat = SessionStat::new(
                    upload_counter.clone(),
                    download_counter.clone(),
                    sess.inbound_tag.clone(),
                    sess.destination.clone(),
                );
                let stat_stream = Box::new(StatProxyStream(
                    stream,
                    upload_counter,
                    download_counter,
                    self.tx.clone(),
                ));
                let key = stat_stream.as_ref() as *const _ as usize;
                self.sessions.lock().await.insert(key, stat);
                Ok(stat_stream)
            }
            None => unimplemented!(),
        }
    }
}
