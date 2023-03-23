extern crate tunio;
use tunio::traits::{DriverT, InterfaceT};
use tunio::{DefaultAsyncInterface, DefaultDriver};
use tunio::platform::wintun::AsyncInterface;
use ipnet::IpNet;
use std::io;

use core::pin::Pin;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use core::task::{Context, Poll};
use tokio_util::codec::Framed;
use anyhow::{anyhow,Result};
use futures;
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use tokio_util::compat::Compat;

use super::codec::*;


#[derive(Clone, Debug, Default)]
pub struct Configuration {
    pub(crate) name: Option<String>,

    pub(crate) ipnet: Option<IpNet>,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) broadcast: Option<IpAddr>,
    pub(crate) mtu: Option<i32>,
    pub(crate) enabled: Option<bool>,
    #[cfg(not(target_os = "windows"))]
    pub(crate) raw_fd: Option<RawFd>,
}

impl Configuration {

    /// Set the name.
    pub fn name<S: AsRef<str>>(&mut self, name: S) -> &mut Self {
        log::debug!("set tun name {:?}",name.as_ref());
        self.name = Some(name.as_ref().into());
        self
    }

    /// Set the address.
    pub fn address<S: AsRef<str>>(&mut self, value: S) -> &mut Self {
        log::debug!("set tun address {:?}",value.as_ref());
        if let Ok(ipnet) = value.as_ref().parse() {
            self.ipnet = Some(ipnet);
        }
        else {
            let address:IpAddr = value.as_ref().parse().expect("parsing tun address failed.");
            self.ipnet = Some(address.into());
        }
        self
    }

    /// Set the destination address.
    pub fn destination<S: AsRef<str>>(&mut self, value: S) -> &mut Self {
        log::warn!("tunio_wrapper: destination setting is not implemented");
        self.destination = Some(value.as_ref().parse().expect("parsing destination address failed."));
        self
    }

    /// Set the broadcast address.
    pub fn broadcast<S: AsRef<str>>(&mut self, value: S) -> &mut Self {
        self.broadcast = Some(value.as_ref().parse().expect("parsing tun broadcast address failed."));
        self
    }

    /// Set the netmask.
    pub fn netmask<S: AsRef<str>>(&mut self, value: S) -> &mut Self {
        if value.as_ref().is_empty()
        {
            return self;
        }
        if let Some(ipnet) = self.ipnet{
            self.ipnet = Some(IpNet::with_netmask(ipnet.addr(), 
            value.as_ref().parse().expect("parsing tun netmask failed."))
            .expect("tun netmask incompatible with address"));
        }
        else {
            log::error!("tun: set address before setting netmask");
        }
        self
    }

    /// Set the MTU.
    pub fn mtu(&mut self, value: i32) -> &mut Self {
        self.mtu = Some(value);
        self
    }

    /// Set the interface to be enabled once created.
    pub fn up(&mut self) -> &mut Self {
        self.enabled = Some(true);
        self
    }

    /// Set the interface to be disabled once created.
    pub fn down(&mut self) -> &mut Self {
        self.enabled = Some(false);
        self
    }

    /// Set the raw fd.
    #[cfg(not(target_os = "windows"))]
    pub fn raw_fd(&mut self, fd: RawFd) -> &mut Self {
        self.raw_fd = Some(fd);
        self
    }
}

pub struct AsyncDevice {
    interface: AsyncInterface,
}

impl AsyncDevice {
    /// Returns a mutable reference to the underlying Device object
    // pub fn get_mut(&mut self) -> &mut AsyncInterface {
    //     self.interface.get_mut()
    // }
    /// Consumes this AsyncDevice and return a Framed object (unified Stream and Sink interface)
    pub fn into_framed(mut self) -> Framed<Compat<AsyncInterface>, TunPacketCodec> {
        let pi = false;
        let mtu = self.interface.handle().mtu().unwrap_or(1504);
        let codec = TunPacketCodec::new(pi, mtu.try_into().unwrap());
        Framed::new(self.interface.compat(), codec)
    }
}

pub fn create_as_async(conf: &Configuration) -> Result<AsyncDevice> {
    let mut driver = DefaultDriver::new().unwrap();
    let mut interface_config = DefaultAsyncInterface::config_builder();
    if let Some(name) = &conf.name {
        interface_config.name(name.clone());
    }

    #[cfg(target_os = "windows")]
    interface_config
        .platform(|mut b| b.description("description".into()).build())?;
    let interface_config = interface_config.build().unwrap();

    log::debug!("create and start tun device");
    let interface;
    if let Some(enabled) = conf.enabled {
        if(enabled){
            interface = DefaultAsyncInterface::new_up(&mut driver, interface_config).unwrap();
        }
        else {
            interface = DefaultAsyncInterface::new(&mut driver, interface_config).unwrap();
        }
    }
    else {
        interface = DefaultAsyncInterface::new(&mut driver, interface_config).unwrap();
    }
    let iff = interface.handle();

    if let Some(ipnet) = conf.ipnet {
        iff.add_address(ipnet)
        .map_err(|err|anyhow!(err.to_string()))?;
    }
    if let Some(mtu) = conf.mtu {
        iff.set_mtu(mtu.try_into().unwrap())
        .map_err(|err|anyhow!(err.to_string()))?;
    }

    // TODO destination set 
    let device = AsyncDevice{interface: interface};
    Ok(device)
}