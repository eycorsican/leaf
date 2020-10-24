use std::sync::Arc;

use anyhow::Result;
use futures::{sink::SinkExt, stream::StreamExt};
use log::*;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;
use tun::{self, Device, TunPacket};

use crate::{
    app::dispatcher::Dispatcher,
    app::nat_manager::NatManager,
    common::fake_dns::FakeDns,
    config::{Inbound, TUNInboundSettings},
    Runner,
};

use super::netstack::NetStack;

const MTU: usize = 1500;

pub fn new(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> Result<Runner> {
    let settings = protobuf::parse_from_bytes::<TUNInboundSettings>(&inbound.settings).unwrap();

    let cfg = if settings.fd >= 0 {
        let mut cfg = tun::Configuration::default();
        cfg.raw_fd(settings.fd);
        cfg
    } else {
        let mut cfg = tun::Configuration::default();
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
        cfg
    };

    // #[cfg(target_os = "linux")]
    // cfg.platform(|cfg| {
    //     cfg.packet_information(true);
    // });

    let fake_dns_exclude = settings.fake_dns_exclude;

    Ok(Box::pin(async move {
        let tun = tun::create_as_async(&cfg).unwrap();

        let fakedns = Arc::new(TokioMutex::new(FakeDns::new()));
        for domain in fake_dns_exclude.into_iter() {
            fakedns.lock().await.exclude(domain);
        }

        let stack = NetStack::new(dispatcher, nat_manager, fakedns);

        let mtu = tun.get_ref().mtu().unwrap_or(MTU as i32);
        let framed = tun.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_reader, mut stack_writer) = io::split(stack);

        let s2t = async move {
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
        };

        let t2s = async move {
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
        };

        info!("tun inbound started");

        tokio::select! {
            r1 = t2s => debug!("s2t ended {:?}", r1),
            r2 = s2t => debug!("s2t ended {:?}", r2)
        }
    }))
}
