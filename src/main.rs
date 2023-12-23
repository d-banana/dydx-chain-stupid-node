use clap::{Parser};
use dydx_chain_stupid_node::connection::Connection;

/// A stupidly simple implementation of the DYDX Chain, to better understand CometBFT, Cosmos SDK and DYDX, using Rust.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
}

fn main() {
        let _args = Args::parse();
        let peer = Connection::try_new([127, 0, 0, 1], 26656)
                .unwrap();
        peer.listen();
        loop {
        }
}
