use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::sync::Arc;

use async_ffi::BorrowingFfiFuture;
use async_trait::async_trait;
use libloading::Library;

use crate::{proxy::*, session::Session};

pub struct PluginSpec {
    pub add_handler_fn: unsafe fn(&mut dyn PluginRegistrar, &str, args: &str),
}

pub trait PluginRegistrar {
    fn add_handler(
        &mut self,
        tag: &str,
        tcp_handler: AnyExternalTcpOutboundHandler,
        udp_handler: AnyExternalUdpOutboundHandler,
    );
}

pub trait ExternalTcpOutboundHandler: Send + Sync + Unpin {
    type Stream;

    fn connect_addr(&self) -> Option<OutboundConnect>;

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> BorrowingFfiFuture<'a, io::Result<Self::Stream>>;
}
pub type AnyExternalTcpOutboundHandler = Arc<dyn ExternalTcpOutboundHandler<Stream = AnyStream>>;

pub trait ExternalUdpOutboundHandler: Send + Sync + Unpin {
    type Stream;
    type Datagram;

    fn connect_addr(&self) -> Option<OutboundConnect>;

    fn transport_type(&self) -> DatagramTransportType;

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::Stream, Self::Datagram>>,
    ) -> BorrowingFfiFuture<'a, io::Result<Self::Datagram>>;
}

struct PluginRegistrarImpl {
    tcp_handlers: HashMap<String, TcpOutboundHandlerProxy>,
    udp_handlers: HashMap<String, UdpOutboundHandlerProxy>,
    lib: Arc<Library>,
}

impl PluginRegistrarImpl {
    fn new(lib: Arc<Library>) -> Self {
        Self {
            lib,
            tcp_handlers: HashMap::new(),
            udp_handlers: HashMap::new(),
        }
    }
}

impl PluginRegistrar for PluginRegistrarImpl {
    fn add_handler(
        &mut self,
        tag: &str,
        tcp_handler: AnyExternalTcpOutboundHandler,
        udp_handler: AnyExternalUdpOutboundHandler,
    ) {
        let tcp_proxy = TcpOutboundHandlerProxy {
            handler: tcp_handler,
            _lib: Arc::clone(&self.lib),
        };
        let udp_proxy = UdpOutboundHandlerProxy {
            handler: udp_handler,
            _lib: Arc::clone(&self.lib),
        };
        self.tcp_handlers.insert(tag.to_string(), tcp_proxy);
        self.udp_handlers.insert(tag.to_string(), udp_proxy);
    }
}

pub struct TcpOutboundHandlerProxy {
    handler: AnyExternalTcpOutboundHandler,
    _lib: Arc<Library>,
}

impl TcpOutboundHandlerProxy {
    fn get_handler(&self) -> AnyExternalTcpOutboundHandler {
        self.handler.clone()
    }
}

impl ExternalTcpOutboundHandler for TcpOutboundHandlerProxy {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.handler.connect_addr()
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> BorrowingFfiFuture<'a, io::Result<Self::Stream>> {
        self.handler.handle(sess, stream)
    }
}

pub struct UdpOutboundHandlerProxy {
    handler: AnyExternalUdpOutboundHandler,
    _lib: Arc<Library>,
}

impl UdpOutboundHandlerProxy {
    fn get_handler(&self) -> AnyExternalUdpOutboundHandler {
        self.handler.clone()
    }
}

impl ExternalUdpOutboundHandler for UdpOutboundHandlerProxy {
    type Stream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.handler.connect_addr()
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.handler.transport_type()
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::Stream, Self::Datagram>>,
    ) -> BorrowingFfiFuture<'a, io::Result<Self::Datagram>> {
        self.handler.handle(sess, transport)
    }
}

pub type AnyExternalUdpOutboundHandler =
    Arc<dyn ExternalUdpOutboundHandler<Stream = AnyStream, Datagram = AnyOutboundDatagram>>;

#[derive(Default)]
pub struct ExternalHandlers {
    tcp_handlers: HashMap<String, TcpOutboundHandlerProxy>,
    udp_handlers: HashMap<String, UdpOutboundHandlerProxy>,
    libraries: HashMap<String, Arc<Library>>,
}

impl ExternalHandlers {
    pub fn new() -> Self {
        Self::default()
    }

    pub unsafe fn new_handler<P>(&mut self, path: P, tag: &str, args: &str) -> io::Result<()>
    where
        P: AsRef<OsStr> + ToString + Clone,
    {
        let lib = if let Some(lib) = self.libraries.get(&path.to_string()) {
            lib.clone()
        } else {
            let lib = Arc::new(Library::new(path.clone()).unwrap());
            self.libraries.insert(path.to_string(), lib.clone());
            lib
        };

        let plugin = lib.get::<*mut PluginSpec>(b"plugin_spec\0").unwrap().read();
        let mut registrar = PluginRegistrarImpl::new(Arc::clone(&lib));
        (plugin.add_handler_fn)(&mut registrar, tag, args);
        self.tcp_handlers.extend(registrar.tcp_handlers);
        self.udp_handlers.extend(registrar.udp_handlers);
        Ok(())
    }

    pub fn get_tcp_handler(&self, name: &str) -> Option<AnyExternalTcpOutboundHandler> {
        self.tcp_handlers.get(name).map(|h| h.get_handler())
    }

    pub fn get_udp_handler(&self, name: &str) -> Option<AnyExternalUdpOutboundHandler> {
        self.udp_handlers.get(name).map(|h| h.get_handler())
    }
}

pub struct ExternalTcpOutboundHandlerProxy(pub AnyExternalTcpOutboundHandler);

#[async_trait]
impl TcpOutboundHandler for ExternalTcpOutboundHandlerProxy {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.0.connect_addr()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        self.0.handle(sess, stream).await
    }
}

pub struct ExternalUdpOutboundHandlerProxy(pub AnyExternalUdpOutboundHandler);

#[async_trait]
impl UdpOutboundHandler for ExternalUdpOutboundHandlerProxy {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.0.connect_addr()
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.0.transport_type()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        self.0.handle(sess, transport).await
    }
}
