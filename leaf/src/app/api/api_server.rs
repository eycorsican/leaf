use std::collections::HashSet;
use std::convert::Infallible;
use std::iter::FromIterator;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use tracing::info;

#[cfg(feature = "outbound-select")]
use axum::extract::Query;

use crate::RuntimeManager;

mod models {
    use serde_derive::{Deserialize, Serialize};

    #[cfg(feature = "outbound-select")]
    #[derive(Debug, Deserialize)]
    pub struct SelectOptions {
        pub outbound: Option<String>,
        pub select: Option<String>,
    }

    #[cfg(feature = "outbound-select")]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct SelectReply {
        pub selected: Option<String>,
    }

    #[cfg(feature = "stat")]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Stat {
        pub network: String,
        pub inbound_tag: String,
        pub forwarded_source: Option<String>,
        pub source: String,
        pub destination: String,
        pub outbound_tag: String,
        pub bytes_sent: u64,
        pub bytes_recvd: u64,
        pub send_completed: bool,
        pub recv_completed: bool,
    }
}

mod handlers {
    use super::*;

    #[cfg(feature = "outbound-select")]
    pub async fn select_update(
        Query(opts): Query<models::SelectOptions>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<StatusCode, Infallible> {
        if let models::SelectOptions {
            outbound: Some(outbound),
            select: Some(select),
        } = opts
        {
            if rm.set_outbound_selected(&outbound, &select).await.is_ok() {
                return Ok(StatusCode::OK);
            }
        }
        Ok(StatusCode::ACCEPTED)
    }

    #[cfg(feature = "outbound-select")]
    pub async fn select_get(
        Query(opts): Query<models::SelectOptions>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Json<models::SelectReply>, Infallible> {
        if let models::SelectOptions {
            outbound: Some(outbound),
            ..
        } = opts
        {
            if let Ok(selected) = rm.get_outbound_selected(&outbound).await {
                return Ok(Json(models::SelectReply {
                    selected: Some(selected),
                }));
            }
        }
        Ok(Json(models::SelectReply { selected: None }))
    }

    #[cfg(feature = "outbound-select")]
    pub async fn select_list(
        Query(opts): Query<models::SelectOptions>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Json<Vec<String>>, Infallible> {
        if let models::SelectOptions {
            outbound: Some(outbound),
            ..
        } = opts
        {
            if let Ok(selects) = rm.get_outbound_selects(&outbound).await {
                return Ok(Json(selects));
            }
        }
        Ok(Json(Vec::new()))
    }

    pub async fn runtime_reload(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<StatusCode, Infallible> {
        if rm.reload().await.is_ok() {
            Ok(StatusCode::OK)
        } else {
            Ok(StatusCode::ACCEPTED)
        }
    }

    pub async fn runtime_shutdown(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<StatusCode, Infallible> {
        if rm.shutdown().await {
            Ok(StatusCode::OK)
        } else {
            Ok(StatusCode::ACCEPTED)
        }
    }

    #[cfg(feature = "stat")]
    pub async fn stat_json(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Json<Vec<models::Stat>>, Infallible> {
        let mut stats = Vec::new();
        let sm = rm.stat_manager();
        let sm = sm.read().await;
        for c in sm.counters.iter() {
            stats.push(models::Stat {
                network: c.sess.network.to_string(),
                inbound_tag: c.sess.inbound_tag.to_owned(),
                forwarded_source: c.sess.forwarded_source.map(|x| x.to_string()),
                source: c.sess.source.to_string(),
                destination: c.sess.destination.to_string(),
                outbound_tag: c.sess.outbound_tag.to_owned(),
                bytes_sent: c.bytes_sent(),
                bytes_recvd: c.bytes_recvd(),
                send_completed: c.send_completed(),
                recv_completed: c.recv_completed(),
            });
        }
        Ok(Json(stats))
    }

    #[cfg(feature = "stat")]
    pub async fn stat_html(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Html<String>, Infallible> {
        let mut body = String::from(
            r#"<html>
<head><style>
table, th, td {
  border: 1px solid black;
  border-collapse: collapse;
  text-align: right;
  padding: 4;
  font-size: small;
}
.highlight {
  font-weight: bold;
}
</style></head>
<table style="border=4px solid">
        "#,
        );
        let sm = rm.stat_manager();
        let sm = sm.read().await;
        let total_counters = sm.counters.len();
        let active_counters = sm
            .counters
            .iter()
            .filter(|x| !x.send_completed() || !x.recv_completed())
            .count();
        let active_sources = HashSet::<IpAddr>::from_iter(
            sm.counters
                .iter()
                .filter(|x| !x.send_completed() || !x.recv_completed())
                .map(|c| c.sess.source.ip()),
        )
        .len();
        let active_forwarded_source = HashSet::<IpAddr>::from_iter(
            sm.counters
                .iter()
                .filter(|x| !x.send_completed() || !x.recv_completed())
                .filter_map(|c| c.sess.forwarded_source),
        )
        .len();
        body.push_str(&format!(
            "Total {}<br>Active {}<br>Active Source {}<br>Active Forwarded Source {}<br><br>",
            total_counters, active_counters, active_sources, active_forwarded_source,
        ));
        body.push_str("<tr><td>Network</td><td>Inbound</td><td>Forwarded</td><td>Source</td><td>Destination</td><td>Outbound</td><td>SentBytes</td><td>RecvdBytes</td><td>SendFin</td><td>RecvFin</td></tr>");
        for c in sm.counters.iter() {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                &c.sess.network,
                &c.sess.inbound_tag,
                &c.sess.forwarded_source.map(|x|x.to_string()).unwrap_or("None".to_string()),
                &c.sess.source,
                &c.sess.destination,
                &c.sess.outbound_tag,
                c.bytes_sent(),
                c.bytes_recvd(),
                c.send_completed(),
                c.recv_completed(),
            ));
        }
        body.push_str("</table></html>");
        Ok(Html(body))
    }
}

pub struct ApiServer {
    runtime_manager: Arc<RuntimeManager>,
}

impl ApiServer {
    pub fn new(runtime_manager: Arc<RuntimeManager>) -> Self {
        Self { runtime_manager }
    }

    pub fn serve(&self, listen_addr: SocketAddr) -> crate::Runner {
        let mut app = Router::new()
            .route("/api/v1/runtime/reload", post(handlers::runtime_reload))
            .route("/api/v1/runtime/shutdown", post(handlers::runtime_shutdown));

        #[cfg(feature = "outbound-select")]
        {
            app = app
                .route("/api/v1/app/outbound/select", post(handlers::select_update))
                .route("/api/v1/app/outbound/select", get(handlers::select_get))
                .route("/api/v1/app/outbound/selects", get(handlers::select_list));
        }

        #[cfg(feature = "stat")]
        {
            app = app
                .route("/api/v1/runtime/stat/html", get(handlers::stat_html))
                .route("/api/v1/runtime/stat/json", get(handlers::stat_json));
        }

        let app = app.with_state(self.runtime_manager.clone());

        info!("api server listening tcp {}", &listen_addr);

        Box::pin(async move {
            let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        })
    }
}
