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
        /* Remote peer
        let peer = Peer::try_new_tcp(
                &Config::default(),
                [135, 181, 5, 219],
                23856,
                Some(hex::decode("ade4d8bc8cbe014af6ebdf3cb7b1e9ad36f412c0")
                        .expect("hex to bytes")
                        .try_into()
                        .expect("fixed size"))
        ).expect("Failed to make new peer tcp");
         */
        let peer = Peer::try_new_tcp(
                &Config::default(),
                [127, 0, 0, 1],
                26656,
                Some(hex::decode("f9b012d67cb64747eca5fbc1b8a213638cffc870")
                        .expect("hex to bytes")
                        .try_into()
                        .expect("fixed size"))
        ).expect("Failed to make new peer tcp");
        peer.run();
        loop {
        }
}
