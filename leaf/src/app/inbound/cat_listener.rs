use std::net::SocketAddr;
use std::sync::Arc;
use std::{io, pin::Pin};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::task::{Context, Poll};
use futures::TryFutureExt;
use protobuf::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tracing::{debug, info};

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::config::{CatInboundSettings, Inbound};
use crate::proxy::*;
use crate::session::*;
use crate::Runner;

struct Stream {
    input: tokio::io::Stdin,
    output: tokio::io::Stdout,
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.input).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.output).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.output).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.output).poll_shutdown(cx)
    }
}

struct Datagram {
    input: tokio::io::Stdin,
    output: tokio::io::Stdout,
    target: SocksAddr,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf(self.input, self.target)),
            Box::new(DatagramSendHalf(self.output)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "cannot convert stdin to UDP socket",
        ))
    }
}

struct DatagramRecvHalf(tokio::io::Stdin, SocksAddr);

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        mut buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        self.0
            .read_buf(&mut buf)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .map_ok(|n| {
                (
                    n,
                    DatagramSource::new("0.0.0.0:0".parse::<SocketAddr>().unwrap(), None),
                    self.1.clone(),
                )
            })
            .await
    }
}

struct DatagramSendHalf(tokio::io::Stdout);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        _src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.0.write_all(buf).map_ok(|_| buf.len()).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

pub struct CatInboundListener {
    pub inbound: Inbound,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

impl CatInboundListener {
    pub fn listen(&self) -> Result<Runner> {
        let inbound_tag = self.inbound.tag.clone();
        let settings = CatInboundSettings::parse_from_bytes(&self.inbound.settings)?;
        let dispatcher = self.dispatcher.clone();
        let nat_manager = self.nat_manager.clone();
        let target = SocksAddr::from(
            format!("{}:{}", settings.address, settings.port).parse::<SocketAddr>()?,
        );
        let network = match settings.network.to_lowercase().as_str() {
            "tcp" => Network::Tcp,
            "udp" => Network::Udp,
            _ => return Err(anyhow!("unknown network {}", settings.network)),
        };
        info!("reading stdin to target {}:{}", network, &target);
        Ok(Box::pin(async move {
            let sess = Session {
                network: network,
                destination: target,
                ..Default::default()
            };
            match network {
                Network::Tcp => {
                    let stream = Box::new(Stream {
                        input: tokio::io::stdin(),
                        output: tokio::io::stdout(),
                    });
                    dispatcher.dispatch_stream(sess, stream).await;
                }
                Network::Udp => {
                    let dgram = Box::new(Datagram {
                        input: tokio::io::stdin(),
                        output: tokio::io::stdout(),
                        target: sess.destination.clone(),
                    });

                    let sess = Some(sess);

                    let (mut lr, mut ls) = dgram.split();

                    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
                        tokio_channel(*crate::option::UDP_UPLINK_CHANNEL_SIZE);

                    tokio::spawn(async move {
                        while let Some(pkt) = l_rx.recv().await {
                            let dst_addr = pkt.dst_addr.must_ip();
                            if let Err(e) =
                                ls.send_to(&pkt.data[..], &pkt.src_addr, &dst_addr).await
                            {
                                debug!("Send datagram failed: {}", e);
                                break;
                            }
                        }
                        if let Err(e) = ls.close().await {
                            debug!("Failed to close inbound datagram: {}", e);
                        }
                    });

                    let mut buf = vec![0u8; *crate::option::DATAGRAM_BUFFER_SIZE * 1024];
                    loop {
                        match lr.recv_from(&mut buf).await {
                            Err(ProxyError::DatagramFatal(e)) => {
                                debug!("Fatal error when receiving datagram: {}", e);
                                break;
                            }
                            Err(ProxyError::DatagramWarn(e)) => {
                                debug!("Warning when receiving datagram: {}", e);
                                continue;
                            }
                            Ok((n, dgram_src, dst_addr)) => {
                                let pkt = UdpPacket::new(
                                    (&buf[..n]).to_vec(),
                                    SocksAddr::from(dgram_src.address),
                                    dst_addr,
                                );
                                nat_manager
                                    .send(sess.as_ref(), &dgram_src, &inbound_tag, &l_tx, pkt)
                                    .await;
                            }
                        }
                    }
                }
            }
            info!("cat done");
        }))
    }
}
