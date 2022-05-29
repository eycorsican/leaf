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
        stream_handler: AnyExternalOutboundStreamHandler,
        datagram_handler: AnyExternalOutboundDatagramHandler,
    );
}

pub trait ExternalOutboundStreamHandler: Send + Sync + Unpin {
    fn connect_addr(&self) -> Option<OutboundConnect>;

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>>;
}
pub type AnyExternalOutboundStreamHandler = Arc<dyn ExternalOutboundStreamHandler>;

pub trait ExternalOutboundDatagramHandler: Send + Sync + Unpin {
    fn connect_addr(&self) -> Option<OutboundConnect>;

    fn transport_type(&self) -> DatagramTransportType;

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyOutboundDatagram>>;
}

struct PluginRegistrarImpl {
    stream_handlers: HashMap<String, OutboundStreamHandlerProxy>,
    datagram_handlers: HashMap<String, OutboundDatagramHandlerProxy>,
    lib: Arc<Library>,
}

impl PluginRegistrarImpl {
    fn new(lib: Arc<Library>) -> Self {
        Self {
            lib,
            stream_handlers: HashMap::new(),
            datagram_handlers: HashMap::new(),
        }
    }
}

impl PluginRegistrar for PluginRegistrarImpl {
    fn add_handler(
        &mut self,
        tag: &str,
        stream_handler: AnyExternalOutboundStreamHandler,
        datagram_handler: AnyExternalOutboundDatagramHandler,
    ) {
        let tcp_proxy = OutboundStreamHandlerProxy {
            handler: stream_handler,
            _lib: Arc::clone(&self.lib),
        };
        let udp_proxy = OutboundDatagramHandlerProxy {
            handler: datagram_handler,
            _lib: Arc::clone(&self.lib),
        };
        self.stream_handlers.insert(tag.to_string(), tcp_proxy);
        self.datagram_handlers.insert(tag.to_string(), udp_proxy);
    }
}

pub struct OutboundStreamHandlerProxy {
    handler: AnyExternalOutboundStreamHandler,
    _lib: Arc<Library>,
}

impl OutboundStreamHandlerProxy {
    fn get_handler(&self) -> AnyExternalOutboundStreamHandler {
        self.handler.clone()
    }
}

impl ExternalOutboundStreamHandler for OutboundStreamHandlerProxy {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.handler.connect_addr()
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
        self.handler.handle(sess, stream)
    }
}

pub struct OutboundDatagramHandlerProxy {
    handler: AnyExternalOutboundDatagramHandler,
    _lib: Arc<Library>,
}

impl OutboundDatagramHandlerProxy {
    fn get_handler(&self) -> AnyExternalOutboundDatagramHandler {
        self.handler.clone()
    }
}

impl ExternalOutboundDatagramHandler for OutboundDatagramHandlerProxy {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.handler.connect_addr()
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.handler.transport_type()
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyOutboundDatagram>> {
        self.handler.handle(sess, transport)
    }
}

pub type AnyExternalOutboundDatagramHandler = Arc<dyn ExternalOutboundDatagramHandler>;

#[derive(Default)]
pub struct ExternalHandlers {
    stream_handlers: HashMap<String, OutboundStreamHandlerProxy>,
    datagram_handlers: HashMap<String, OutboundDatagramHandlerProxy>,
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
        self.stream_handlers.extend(registrar.stream_handlers);
        self.datagram_handlers.extend(registrar.datagram_handlers);
        Ok(())
    }

    pub fn get_stream_handler(&self, name: &str) -> Option<AnyExternalOutboundStreamHandler> {
        self.stream_handlers.get(name).map(|h| h.get_handler())
    }

    pub fn get_datagram_handler(&self, name: &str) -> Option<AnyExternalOutboundDatagramHandler> {
        self.datagram_handlers.get(name).map(|h| h.get_handler())
    }
}

pub struct ExternalOutboundStreamHandlerProxy(pub AnyExternalOutboundStreamHandler);

#[async_trait]
impl OutboundStreamHandler for ExternalOutboundStreamHandlerProxy {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.0.connect_addr()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        self.0.handle(sess, stream).await
    }
}

pub struct ExternalOutboundDatagramHandlerProxy(pub AnyExternalOutboundDatagramHandler);

#[async_trait]
impl OutboundDatagramHandler for ExternalOutboundDatagramHandlerProxy {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.0.connect_addr()
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.0.transport_type()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        self.0.handle(sess, transport).await
    }
}
