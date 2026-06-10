use clap::Parser;
use iris_compiler::*;
use iris_core::{config::load_config, Runtime};
use iris_datatypes::{QuicStream, TlsHandshake};
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
}

#[callback("tcp,level=InL4Conn")]
fn log_packet(tls: &TlsHandshake) -> bool {
    true
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
