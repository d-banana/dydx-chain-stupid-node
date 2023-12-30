use std::path::Path;

fn main() {
        protobuf_codegen::Codegen::new()
                .include("proto")
                .inputs(
                        Path::new("proto")
                                .read_dir()
                                .unwrap()
                                .map(|p| p.unwrap().path())
                )
                .cargo_out_dir("proto_rust")
                .run_from_script();
}