use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::app::outbound::manager::OutboundManager;

pub struct ApiServer {
    listen_addr: SocketAddr,
    outbound_manager: Arc<OutboundManager>,
}

mod models {
    use serde_derive::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct SelectOptions {
        pub outbound: Option<String>,
        pub select: Option<String>,
    }
}

mod handlers {
    use super::*;
    use warp::http::StatusCode;

    pub async fn select_update(
        opts: models::SelectOptions,
        obm: Arc<OutboundManager>,
    ) -> Result<impl warp::Reply, Infallible> {
        if let models::SelectOptions {
            outbound: Some(outbound),
            select: Some(select),
        } = opts
        {
            if let Some(selector) = obm.get_selector(&outbound) {
                if selector.write().await.set_selected(&select).is_ok() {
                    return Ok(StatusCode::OK);
                }
            }
        }
        Ok(StatusCode::ACCEPTED)
    }
}

mod filters {
    use super::*;
    use warp::Filter;

    fn with_outbound_manager(
        obm: Arc<OutboundManager>,
    ) -> impl Filter<Extract = (Arc<OutboundManager>,), Error = Infallible> + Clone {
        warp::any().map(move || obm.clone())
    }

    // PUT /api/v1/app/outbound/select?outbound=Proxy&select=p3
    pub fn select_update(
        obm: Arc<OutboundManager>,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("api" / "v1" / "app" / "outbound" / "select")
            .and(warp::put())
            .and(warp::query::<models::SelectOptions>())
            .and(with_outbound_manager(obm))
            .and_then(handlers::select_update)
    }
}

impl ApiServer {
    pub fn new(outbound_manager: Arc<OutboundManager>) -> Self {
        let listen_addr = "127.0.0.1:9991".parse().unwrap();
        Self {
            listen_addr,
            outbound_manager,
        }
    }

    pub fn serve(&self, rt: &tokio::runtime::Runtime) -> crate::Runner {
        let routes = filters::select_update(self.outbound_manager.clone());
        Box::pin(rt.block_on(async { warp::serve(routes).bind(self.listen_addr) }))
    }
}
