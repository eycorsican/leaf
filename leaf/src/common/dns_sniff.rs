use std::io;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;
use lru::LruCache;
use tokio::sync::RwLock;

use crate::proxy::{OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::session::SocksAddr;

#[derive(Clone)]
pub struct DnsSniffer {
    cache: Arc<RwLock<LruCache<IpAddr, String>>>,
}

impl DnsSniffer {
    pub fn new() -> Self {
        let cap = NonZeroUsize::new(2048).unwrap();
        DnsSniffer {
            cache: Arc::new(RwLock::new(LruCache::new(cap))),
        }
    }

    pub async fn add(&self, ip: IpAddr, domain: String) {
        self.cache.write().await.put(ip, domain);
    }

    pub async fn get(&self, ip: &IpAddr) -> Option<String> {
        self.cache.read().await.peek(ip).cloned()
    }
}

pub struct SniffingDatagram {
    recv: SniffingDatagramRecvHalf,
    send: SniffingDatagramSendHalf,
}

impl SniffingDatagram {
    pub fn new(outbound: Box<dyn OutboundDatagram>, sniffer: DnsSniffer) -> Self {
        let (recv, send) = outbound.split();
        SniffingDatagram {
            recv: SniffingDatagramRecvHalf {
                inner: recv,
                sniffer: sniffer.clone(),
            },
            send: SniffingDatagramSendHalf { inner: send },
        }
    }
}

impl OutboundDatagram for SniffingDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

pub struct SniffingDatagramRecvHalf {
    inner: Box<dyn OutboundDatagramRecvHalf>,
    sniffer: DnsSniffer,
}

#[async_trait::async_trait]
impl OutboundDatagramRecvHalf for SniffingDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (len, src_addr) = self.inner.recv_from(buf).await?;

        if let Ok(msg) = Message::from_vec(&buf[..len]) {
            if msg.message_type() == MessageType::Response {
                // Extract domain from the first query in the response
                let domain = if let Some(query) = msg.queries().first() {
                    let mut name = query.name().to_string();
                    if name.ends_with('.') {
                        name.pop();
                    }
                    Some(name)
                } else {
                    None
                };

                if let Some(domain) = domain {
                    for answer in msg.answers() {
                        if let Some(rdata) = answer.data() {
                            match rdata {
                                RData::A(ip) => {
                                    self.sniffer.add(IpAddr::V4(ip.0), domain.clone()).await;
                                }
                                RData::AAAA(ip) => {
                                    self.sniffer.add(IpAddr::V6(ip.0), domain.clone()).await;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        Ok((len, src_addr))
    }
}

pub struct SniffingDatagramSendHalf {
    inner: Box<dyn OutboundDatagramSendHalf>,
}

#[async_trait::async_trait]
impl OutboundDatagramSendHalf for SniffingDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        self.inner.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
    use crate::session::SocksAddr;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    struct MockOutboundDatagramRecvHalf {
        data: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl OutboundDatagramRecvHalf for MockOutboundDatagramRecvHalf {
        async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
            if self.data.is_empty() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            let len = std::cmp::min(buf.len(), self.data.len());
            buf[..len].copy_from_slice(&self.data[..len]);
            self.data.clear(); // One-shot
            Ok((len, SocksAddr::any_ipv4()))
        }
    }

    struct MockOutboundDatagramSendHalf;

    #[async_trait::async_trait]
    impl OutboundDatagramSendHalf for MockOutboundDatagramSendHalf {
        async fn send_to(&mut self, _buf: &[u8], _dst_addr: &SocksAddr) -> io::Result<usize> {
            Ok(0)
        }
        async fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockOutboundDatagram {
        recv: MockOutboundDatagramRecvHalf,
        send: MockOutboundDatagramSendHalf,
    }

    impl OutboundDatagram for MockOutboundDatagram {
        fn split(
            self: Box<Self>,
        ) -> (
            Box<dyn OutboundDatagramRecvHalf>,
            Box<dyn OutboundDatagramSendHalf>,
        ) {
            (Box::new(self.recv), Box::new(self.send))
        }
    }

    #[tokio::test]
    async fn test_dns_sniff() {
        let sniffer = DnsSniffer::new();

        // Construct a DNS response
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        msg.add_query(query);
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let answer = Record::from_rdata(name, 3600, RData::A(hickory_proto::rr::rdata::A(ip)));
        msg.add_answer(answer);

        let msg_bytes = msg.to_vec().unwrap();

        // Create a mock outbound datagram
        let mock_recv = MockOutboundDatagramRecvHalf { data: msg_bytes };
        let mock_send = MockOutboundDatagramSendHalf;
        let mock_outbound = Box::new(MockOutboundDatagram {
            recv: mock_recv,
            send: mock_send,
        });

        // Create sniffing datagram
        let sniffing_datagram = Box::new(SniffingDatagram::new(mock_outbound, sniffer.clone()));
        let (mut recv, _send) = sniffing_datagram.split();

        // Receive data (trigger sniffing)
        let mut buf = vec![0u8; 1500];
        let (_len, _addr) = recv.recv_from(&mut buf).await.unwrap();

        // Check if sniffed
        let sniffed_ip = IpAddr::V4(ip);
        let domain = sniffer.get(&sniffed_ip).await;
        assert_eq!(domain, Some("example.com".to_string()));
    }
}
