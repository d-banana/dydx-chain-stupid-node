mod handshake;

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use crate::connection::handshake::handshake;
use crate::result::{Error, Result};

pub struct Connection {
        tcp_stream: TcpStream,
}
impl Connection {
        pub fn try_new(ip: [u8; 4], port: u16) -> Result<Self>{
                Ok(Connection {
                        tcp_stream: TcpStream::connect(SocketAddr::new(ip.into(), port))
                                .map_err(Error::TcpStreamConnectFailed)?,
                })
        }

        pub fn listen(&self) -> Result<()> {
                let mut reader = BufReader::new(self.tcp_stream
                        .try_clone()
                        .map_err(Error::TcpStreamCloneFailed)?);
                let is_handshake_done = false;

                thread::spawn(move || {
                        loop {
                                // TODO how to manage the error inside a thread ? close peer connection ?
                                let received = reader
                                        .fill_buf()
                                        .map_err(Error::TcpStreamReadFailed)
                                        .unwrap();

                                if !is_handshake_done {
                                        // TODO Is it the best way to handle the asynchronicity ?
                                        // TODO Listen receive packet => call each function => function try to parse it => return how much to consume or 0/error.
                                        // TODO The first round of packet to start the secure connection is probably different than the future packet how to not make the code ugly ?
                                        if let Ok(read_size) = handshake(received){
                                                reader.consume(read_size);
                                        }
                                }
                        }
                });

                Ok(())
        }
}

mod tests{
        use protobuf::CodedOutputStream;
        use crate::crypto::make_private_public_key_ed25519;

        #[test]
        pub fn handshake_success() {
                let (_, public) = make_private_public_key_ed25519();
                let public = public.as_bytes();
                let mut buffer = Vec::with_capacity(35);
                buffer.push(34);
                CodedOutputStream::new(&mut buffer).write_bytes(1, public);
                println!("{:?}", buffer);
        }
}