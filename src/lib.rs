pub mod peer;
pub mod result;

pub mod proto_rust {
        include!(concat!(env!("OUT_DIR"), "/proto_rust/mod.rs"));
}