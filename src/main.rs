use clap::{Parser};
use dydx_chain_stupid_node::peer::Peer;

/// A stupidly simple implementation of the DYDX Chain, to better understand CometBFT, Cosmos SDK and DYDX, using Rust.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
}

fn main() {
        let _args = Args::parse();
        let peer = Peer::try_new_tcp([127, 0, 0, 1], 26656)
                .unwrap();
        peer.run();
        loop {
        }
}
