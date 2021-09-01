use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::{sink::SinkExt, stream::StreamExt};
use log::*;
use protobuf::Message;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;
use tun::{self, Device, TunPacket};

use crate::{
    app::dispatcher::Dispatcher,
    app::fake_dns::{FakeDns, FakeDnsMode},
    app::nat_manager::NatManager,
    config::{Inbound, TunInboundSettings},
    option, Runner,
};

use super::netstack::NetStack;

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

        let stack = NetStack::new(inbound.tag.clone(), dispatcher, nat_manager, fakedns);

        let mtu = tun.get_ref().mtu().unwrap_or(MTU as i32);
        let framed = tun.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_reader, mut stack_writer) = io::split(stack);

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

        info!("tun inbound started");
        futures::future::select(t2s, s2t).await;
        info!("tun inbound exited");
    }))
}
