use clap::{Parser};
use dydx_chain_stupid_node::config::Config;
use dydx_chain_stupid_node::peer::Peer;

/// A stupidly simple implementation of the DYDX Chain, to better understand CometBFT, Cosmos SDK and DYDX, using Rust.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
}

fn main() {
        let _args = Args::parse();
        let peer = Peer::try_new_tcp(
                &Config::default(),
                [135, 181, 5, 219],
                23856,
                Some([173, 228, 216, 188, 140, 190, 1, 74, 246, 235, 223, 60, 183, 177, 233, 173, 54, 244, 18, 192])
        ).expect("Failed to make new peer tcp");
        peer.run();
        loop {
        }
}
