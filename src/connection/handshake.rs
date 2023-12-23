use curve25519_dalek::{MontgomeryPoint};
use crate::result::{Error, Result};

// TODO need to standardize the consumer of packet
const HANDSHAKE_PACKET_SIZE: usize = 35;
struct RemotePublicED25519(MontgomeryPoint);
impl TryFrom<&[u8]> for RemotePublicED25519 {
        type Error = Error;

        fn try_from(v: &[u8]) -> std::result::Result<Self, Self::Error> {
                let packet_size = v.first()
                        .ok_or(Error::PacketEmpty)?;

                let is_announced_packet_size_correct = (*packet_size) as usize != HANDSHAKE_PACKET_SIZE - 1;
                let is_real_packet_size_correct = v.len() >= HANDSHAKE_PACKET_SIZE;
                if is_announced_packet_size_correct
                        && is_real_packet_size_correct {
                        return Err(Error::HandshakePacketMalformed(v.to_vec()));
                }

                let remote_public_key = MontgomeryPoint(
                        v.get(3..HANDSHAKE_PACKET_SIZE)
                                .unwrap()
                                .try_into()
                                .unwrap()
                );

                Ok(RemotePublicED25519(remote_public_key))
        }
}
pub fn handshake(buffer: &[u8]) -> Result<usize> {
        println!("{:?}", buffer);
        let remote_public: RemotePublicED25519 = buffer.try_into()?;
        println!("{:?}", remote_public.0.0);
        Ok(HANDSHAKE_PACKET_SIZE)
}