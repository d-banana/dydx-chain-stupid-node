extern crate core;

pub mod peer;
pub mod result;
pub mod config;

pub mod proto_rust {
        include!(concat!(env!("OUT_DIR"), "/proto_rust/mod.rs"));
}