use iris_core::{config::load_config, CoreId, Runtime};
use iris_datatypes::{TlsHandshake, ConnRecord};
use iris_datatypes::conn_fts::InterArrivals;
use iris_compiler::*;

mod csv_output;
mod headers;

use flow_features::conn_features::ConnFeatures;
use flow_features::tls_features::TlsFeatures;

// #[callback("tcp or udp,level=L4Terminated")]
// fn flow_cb(
//     conn: &ConnRecord,
//     iat: &InterArrivals,
//     core_id: &CoreId
// ) {
//     if let Some(features) = ConnFeatures::from_conn(conn, iat) {
//         csv_output::write(&features, core_id);
//     }
// }

#[callback("tls or quic,level=L4Terminated")]
fn flow_cb_tls(
    conn: &ConnRecord,
    iat: &InterArrivals,
    proto: &TlsHandshake,
    core_id: &CoreId
) {
    if let (Some(conn_features), Some(tls_features)) = (
        ConnFeatures::from_conn(conn, iat),
        TlsFeatures::from_tls(proto),
    ) {
        csv_output::write_tls(&conn_features, &tls_features, core_id);
    }
}

// #[callback("dns,level=L4Terminated")]
// fn flow_cb_dns(
//     conn: &ConnRecord,
//     iat: &InterArrivals,
//     proto: &DnsTransaction,
//     core_id: &CoreId
// ) {
//     if let (Some(conn_features), Some(dns_features)) = (
//         ConnFeatures::from_conn(conn, iat),
//         DnsFeatures::from_dns(proto, conn.client().ip()),
//     ) {
//         csv_output::write_dns(&conn_features, &dns_features, core_id);
//     }
// }

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    csv_output::combine();
}