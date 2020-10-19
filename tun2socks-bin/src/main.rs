use clap::{App, Arg};
use log::*;
use protobuf::Message;
use tokio::runtime;

use leaf::config::internal;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

#[cfg(target_os = "macos")]
fn default_tun_name() -> &'static str {
    "utun8"
}

#[cfg(target_os = "linux")]
fn default_tun_name() -> &'static str {
    "tun8"
}

fn main() {
    let matches = App::new("tun2socks")
        .version(VERSION.unwrap())
        .about("Turns TCP and UDP traffic into SOCKS-like connections.")
        .arg(
            Arg::new("tun-name")
                .long("tun-name")
                .value_name("NAME")
                .about("Sets the TUN interface name")
                .takes_value(true)
                .default_value(default_tun_name()),
        )
        .arg(
            Arg::new("tun-addr")
                .long("tun-addr")
                .value_name("IP")
                .about("Sets the IP address of the TUN interface")
                .takes_value(true)
                .default_value("10.10.0.2"),
        )
        .arg(
            Arg::new("tun-mask")
                .long("tun-mask")
                .value_name("MASK")
                .about("Sets the network mask of the TUN interface")
                .takes_value(true)
                .default_value("255.255.255.0"),
        )
        .arg(
            Arg::new("tun-gw")
                .long("tun-gw")
                .value_name("GATEWAY")
                .about("Sets the gateway address of the TUN interface")
                .takes_value(true)
                .default_value("10.10.0.1"),
        )
        .arg(
            Arg::new("socks-addr")
                .short('s')
                .long("socks-addr")
                .value_name("ADDRESS")
                .about("Sets the proxy server address")
                .takes_value(true),
        )
        .arg(
            Arg::new("socks-port")
                .short('p')
                .long("socks-port")
                .value_name("PORT")
                .about("Sets the proxy server port")
                .takes_value(true),
        )
        .get_matches();

    let tun_name = matches.value_of("tun-name").unwrap();
    let tun_addr = matches.value_of("tun-addr").unwrap();
    let tun_mask = matches.value_of("tun-mask").unwrap();
    let tun_gw = matches.value_of("tun-gw").unwrap();
    let socks_addr = matches.value_of("socks-addr").unwrap();
    let socks_port = matches
        .value_of("socks-port")
        .unwrap()
        .parse::<u16>()
        .unwrap();

    env_logger::init();

    let mut rt = runtime::Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap();

    let mut inbounds = protobuf::RepeatedField::new();
    let mut inbound = internal::Inbound::new();
    inbound.protocol = "tun".to_string();
    let mut settings = internal::TUNInboundSettings::new();
    settings.fd = -1;
    settings.name = tun_name.to_string();
    settings.address = tun_addr.to_string();
    settings.gateway = tun_gw.to_string();
    settings.netmask = tun_mask.to_string();
    settings.mtu = 1500;
    let mut fake_dns_exclude = protobuf::RepeatedField::new();
    fake_dns_exclude.push("*".to_string());
    settings.fake_dns_exclude = fake_dns_exclude;
    let settings = settings.write_to_bytes().unwrap();
    inbound.settings = settings;
    inbounds.push(inbound);

    let mut outbounds = protobuf::RepeatedField::new();
    let mut outbound = internal::Outbound::new();
    outbound.protocol = "socks".to_string();
    outbound.tag = "socks".to_string();
    let mut settings = internal::SocksOutboundSettings::new();
    settings.address = socks_addr.to_string();
    settings.port = socks_port as u32;
    let settings = settings.write_to_bytes().unwrap();
    outbound.settings = settings;
    outbounds.push(outbound);

    let mut dns = internal::DNS::new();
    let mut servers = protobuf::RepeatedField::new();
    servers.push("1.1.1.1".to_string());
    servers.push("8.8.8.8".to_string());
    dns.servers = servers;
    dns.bind = "0.0.0.0".to_string();

    let mut config = internal::Config::new();
    config.inbounds = inbounds;
    config.outbounds = outbounds;
    config.dns = protobuf::SingularPtrField::some(dns);

    let runners = match leaf::util::create_runners(config) {
        Ok(v) => v,
        Err(e) => {
            error!("create runners fialed: {}", e);
            return;
        }
    };

    rt.block_on(async move {
        futures::future::join_all(runners).await;
    });
}
