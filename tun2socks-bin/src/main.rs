use std::process::exit;

use clap::{App, Arg};
use log::info;
use tokio::runtime;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
const MTU: usize = 1500;

#[cfg(target_os = "macos")]
fn default_tun_name() -> &'static str {
    "utun8"
}

#[cfg(target_os = "linux")]
fn default_tun_name() -> &'static str {
    "tun8"
}

fn main() {
    let matches = App::new("mlo")
        .version(VERSION.unwrap())
        .about("Turns TCP and UDP traffic into SOCKS-like connections.")
        .arg(
            Arg::with_name("tun-name")
                .long("tun-name")
                .value_name("NAME")
                .about("Sets the TUN interface name")
                .takes_value(true)
                .default_value(default_tun_name()),
        )
        .arg(
            Arg::with_name("tun-addr")
                .long("tun-addr")
                .value_name("IP")
                .about("Sets the IP address of the TUN interface")
                .takes_value(true)
                .default_value("10.10.0.2"),
        )
        .arg(
            Arg::with_name("tun-mask")
                .long("tun-mask")
                .value_name("MASK")
                .about("Sets the network mask of the TUN interface")
                .takes_value(true)
                .default_value("255.255.255.0"),
        )
        .arg(
            Arg::with_name("tun-gw")
                .long("tun-gw")
                .value_name("GATEWAY")
                .about("Sets the gateway address of the TUN interface")
                .takes_value(true)
                .default_value("10.10.0.1"),
        )
        .arg(
            Arg::with_name("proxy-type")
                .display_order(1)
                .short('t')
                .long("proxy-type")
                .value_name("TYPE")
                .about("Sets the proxy handler type: [socks, shadowsocks, redirect]")
                .takes_value(true)
                .default_value("socks"),
        )
        .arg(
            Arg::with_name("proxy-server")
                .display_order(2)
                .short('s')
                .long("proxy-server")
                .value_name("IP:PORT")
                .about("Sets the proxy server address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("password")
                .display_order(4)
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                .takes_value(true)
                .about("Sets the password used by shadowsocks handler"),
        )
        .arg(
            Arg::with_name("cipher")
                .display_order(3)
                .short('c')
                .long("cipher")
                .value_name("CIPHER")
                .takes_value(true)
                .about("Sets the cipher used by shadowsocks handler")
                .default_value("chacha20-ietf-poly1305"),
        )
        .arg(
            Arg::with_name("show-ciphers")
                .long("show-ciphers")
                .takes_value(false)
                .about("Shows a list of available shadowsocks ciphers"),
        )
        .arg(
            Arg::with_name("bind")
                .short('B')
                .long("bind")
                .value_name("IP")
                .about("Sets the bind address used by direct handler")
                .takes_value(true),
        )
        .get_matches();

    if matches.is_present("show-ciphers") {
        println!(
            "{:?}",
            shadowsocks::crypto::cipher::CipherType::available_ciphers()
        );
        exit(0);
    }

    let tun_name = matches.value_of("tun-name").unwrap();
    let tun_addr = matches.value_of("tun-addr").unwrap();
    let tun_mask = matches.value_of("tun-mask").unwrap();
    let tun_gw = matches.value_of("tun-gw").unwrap();
    let proxy_type = matches.value_of("proxy-type").unwrap();
    let proxy_server = matches.value_of("proxy-server");
    let password = matches.value_of("password");
    let cipher = matches.value_of("cipher");
    let bind = matches.value_of("bind");

    env_logger::init();

    let mut rt = runtime::Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap();

    let mut cfg = tun::Configuration::default();
    cfg.name(tun_name)
        .address(tun_addr)
        .netmask(tun_mask)
        .destination(tun_gw)
        .mtu(MTU as i32)
        .up();

    #[cfg(target_os = "linux")]
    cfg.platform(|cfg| {
        cfg.packet_information(true);
    });

    let tun = rt.block_on(async { tun::create_as_async(&cfg).unwrap() });
    info!("tun created");

    let stack = rt
        .block_on(tun2socks::util::create_stack(
            proxy_type,
            proxy_server,
            password,
            cipher,
            bind,
        ))
        .unwrap();
    info!("netstack created");

    rt.block_on(tun2socks::new(tun, stack));
}
