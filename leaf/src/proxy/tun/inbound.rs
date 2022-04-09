use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::{sink::SinkExt, stream::StreamExt};
use log::*;
use protobuf::Message;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tokio::sync::Mutex as TokioMutex;
use tun::{self, Device, TunPacket};

use crate::{
    app::dispatcher::Dispatcher,
    app::fake_dns::{FakeDns, FakeDnsMode},
    app::nat_manager::NatManager,
    app::nat_manager::UdpPacket,
    config::{Inbound, TunInboundSettings},
    option,
    session::{DatagramSource, Network, Session, SocksAddr},
    Runner,
};

use super::netstack;

const MTU: usize = 1500;

pub fn new(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> Result<Runner> {
    let settings = TunInboundSettings::parse_from_bytes(&inbound.settings)?;

    let mut cfg = tun::Configuration::default();
    if settings.fd >= 0 {
        cfg.raw_fd(settings.fd);
    } else if settings.auto {
        cfg.name(&*option::DEFAULT_TUN_NAME)
            .address(&*option::DEFAULT_TUN_IPV4_ADDR)
            .destination(&*option::DEFAULT_TUN_IPV4_GW)
            .mtu(1500);

        #[cfg(not(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mipsel",
            target_arch = "mipsel64",
        )))]
        {
            cfg.netmask(&*option::DEFAULT_TUN_IPV4_MASK);
        }

        cfg.up();
    } else {
        cfg.name(settings.name)
            .address(settings.address)
            .destination(settings.gateway)
            .mtu(settings.mtu);

        #[cfg(not(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mipsel",
            target_arch = "mipsel64",
        )))]
        {
            cfg.netmask(settings.netmask);
        }

        cfg.up();
    }

    // FIXME it's a bad design to have 2 lists in config while we need only one
    let fake_dns_exclude = settings.fake_dns_exclude;
    let fake_dns_include = settings.fake_dns_include;
    if !fake_dns_exclude.is_empty() && !fake_dns_include.is_empty() {
        return Err(anyhow!(
            "fake DNS run in either include mode or exclude mode"
        ));
    }
    let (fake_dns_mode, fake_dns_filters) = if !fake_dns_include.is_empty() {
        (FakeDnsMode::Include, fake_dns_include)
    } else {
        (FakeDnsMode::Exclude, fake_dns_exclude)
    };

    let tun = tun::create_as_async(&cfg).map_err(|e| anyhow!("create tun failed: {}", e))?;

    if settings.auto {
        assert!(settings.fd == -1, "tun-auto is not compatible with tun-fd");
    }

    Ok(Box::pin(async move {
        let fakedns = Arc::new(TokioMutex::new(FakeDns::new(fake_dns_mode)));

        for filter in fake_dns_filters.into_iter() {
            fakedns.lock().await.add_filter(filter);
        }

        let lwip_mutex = Arc::new(netstack::LWIPMutex::new());
        let stack = netstack::NetStack::new(lwip_mutex.clone());
        let inbound_tag = inbound.tag.clone();

        let mtu = tun.get_ref().mtu().unwrap_or(MTU as i32);
        let framed = tun.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_reader, mut stack_writer) = io::split(stack);

        let mut futs: Vec<Runner> = Vec::new();

        let s2t = Box::pin(async move {
            let mut buf = vec![0; mtu as usize];
            loop {
                match stack_reader.read(&mut buf).await {
                    Ok(0) => {
                        debug!("read stack eof");
                        return;
                    }
                    Ok(n) => match tun_sink.send(TunPacket::new((&buf[..n]).to_vec())).await {
                        Ok(_) => (),
                        Err(e) => {
                            warn!("send pkt to tun failed: {}", e);
                            return;
                        }
                    },
                    Err(err) => {
                        warn!("read stack failed {:?}", err);
                        return;
                    }
                }
            }
        });
        futs.push(s2t);

        let t2s = Box::pin(async move {
            while let Some(packet) = tun_stream.next().await {
                match packet {
                    Ok(packet) => match stack_writer.write(packet.get_bytes()).await {
                        Ok(_) => (),
                        Err(e) => {
                            warn!("write pkt to stack failed: {}", e);
                            return;
                        }
                    },
                    Err(err) => {
                        warn!("read tun failed {:?}", err);
                        return;
                    }
                }
            }
        });
        futs.push(t2s);

        let fakedns_cloned = fakedns.clone();
        let lwip_mutex_cloned = lwip_mutex.clone();
        let inbound_tag_cloned = inbound_tag.clone();
        let tcp_incoming = Box::pin(async move {
            let mut listener = netstack::TcpListener::new(lwip_mutex_cloned);

            while let Some(stream) = listener.next().await {
                let dispatcher = dispatcher.clone();
                let fakedns = fakedns_cloned.clone();
                let inbound_tag = inbound_tag_cloned.clone();

                tokio::spawn(async move {
                    let mut sess = Session {
                        network: Network::Tcp,
                        source: stream.local_addr().to_owned(),
                        local_addr: stream.remote_addr().to_owned(),
                        destination: SocksAddr::Ip(*stream.remote_addr()),
                        inbound_tag: inbound_tag.clone(),
                        ..Default::default()
                    };

                    if fakedns.lock().await.is_fake_ip(&stream.remote_addr().ip()) {
                        if let Some(domain) = fakedns
                            .lock()
                            .await
                            .query_domain(&stream.remote_addr().ip())
                        {
                            sess.destination =
                                SocksAddr::Domain(domain, stream.remote_addr().port());
                        } else {
                            // Although requests targeting fake IPs are assumed
                            // never happen in real network traffic, which are
                            // likely caused by poisoned DNS cache records, we
                            // still have a chance to sniff the request domain
                            // for TLS traffic in dispatcher.
                            if stream.remote_addr().port() != 443 {
                                return;
                            }
                        }
                    }

                    dispatcher
                        .dispatch_tcp(&mut sess, netstack::TcpStream::new(stream))
                        .await;
                });
            }
        });
        futs.push(tcp_incoming);

        let nat_manager = nat_manager.clone();
        let fakedns = fakedns.clone();
        let udp_incoming = Box::pin(async move {
            let mut listener = netstack::UdpListener::new();
            let nat_manager = nat_manager.clone();
            let fakedns2 = fakedns.clone();
            let pcb = listener.pcb();

            // Sending packets to TUN should be very fast.
            let (client_ch_tx, mut client_ch_rx): (
                TokioSender<UdpPacket>,
                TokioReceiver<UdpPacket>,
            ) = tokio_channel(32);

            // downlink
            let lwip_mutex_cloned = lwip_mutex.clone();
            tokio::spawn(async move {
                while let Some(pkt) = client_ch_rx.recv().await {
                    let socks_src_addr = match pkt.src_addr {
                        Some(a) => a,
                        None => {
                            warn!("unexpected none src addr");
                            continue;
                        }
                    };
                    let dst_addr = match pkt.dst_addr {
                        Some(a) => match a {
                            SocksAddr::Ip(a) => a,
                            _ => {
                                warn!("unexpected domain addr");
                                continue;
                            }
                        },
                        None => {
                            warn!("unexpected dst addr");
                            continue;
                        }
                    };
                    let src_addr = match socks_src_addr {
                        SocksAddr::Ip(a) => a,

                        // If the socket gives us a domain source address,
                        // we assume there must be a paired fake IP, otherwise
                        // we have no idea how to deal with it.
                        SocksAddr::Domain(domain, port) => {
                            // TODO we're doing this for every packet! optimize needed
                            // trace!("downlink querying fake ip for domain {}", &domain);
                            if let Some(ip) = fakedns2.lock().await.query_fake_ip(&domain) {
                                SocketAddr::new(ip, port)
                            } else {
                                warn!(
                                    "unexpected domain src addr {}:{} without paired fake IP",
                                    &domain, &port
                                );
                                continue;
                            }
                        }
                    };
                    netstack::send_udp(
                        lwip_mutex_cloned.clone(),
                        &src_addr,
                        &dst_addr,
                        pcb,
                        &pkt.data[..],
                    );
                }

                error!("unexpected udp downlink ended");
            });

            let fakedns2 = fakedns.clone();

            while let Some(pkt) = listener.next().await {
                if pkt.2.port() == 53 {
                    match fakedns2.lock().await.generate_fake_response(&pkt.0) {
                        Ok(resp) => {
                            netstack::send_udp(
                                lwip_mutex.clone(),
                                &pkt.2,
                                &pkt.1,
                                pcb,
                                resp.as_ref(),
                            );
                            continue;
                        }
                        Err(err) => {
                            trace!("generate fake ip failed: {}", err);
                        }
                    }
                }

                // We're sending UDP packets to a fake IP, and there should be a paired domain,
                // that said, the application connects a UDP socket with a domain address.
                // It also means the back packets on this UDP session shall only come from a
                // single source address.
                let socks_dst_addr = if fakedns2.lock().await.is_fake_ip(&pkt.2.ip()) {
                    // TODO we're doing this for every packet! optimize needed
                    // trace!("uplink querying domain for fake ip {}", &dst_addr.ip(),);
                    if let Some(domain) = fakedns2.lock().await.query_domain(&pkt.2.ip()) {
                        SocksAddr::Domain(domain, pkt.2.port())
                    } else {
                        // Skip this packet. Requests targeting fake IPs are
                        // assumed never happen in real network traffic.
                        continue;
                    }
                } else {
                    SocksAddr::Ip(pkt.2)
                };

                let dgram_src = DatagramSource::new(pkt.1, None);

                let pkt = UdpPacket {
                    data: pkt.0,
                    src_addr: Some(SocksAddr::Ip(dgram_src.address)),
                    dst_addr: Some(socks_dst_addr.clone()),
                };

                nat_manager
                    .send(&dgram_src, socks_dst_addr, &inbound_tag, pkt, &client_ch_tx)
                    .await;
            }
        });
        futs.push(udp_incoming);

        info!("start tun inbound");
        futures::future::select_all(futs).await;
    }))
}
