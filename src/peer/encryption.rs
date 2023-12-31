use chacha20poly1305::ChaCha20Poly1305;

pub struct Encryption{
        pub reader_key: ChaCha20Poly1305,
        pub writer_key: ChaCha20Poly1305,
        pub write_nounce: u128,
        pub read_nounce: u128,
}