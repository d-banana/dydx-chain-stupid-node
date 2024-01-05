use protobuf::CodedOutputStream;
use merlin::Transcript;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use protobuf::Message;
use x25519_dalek::{SharedSecret, PublicKey as EphemeralPublic};
use ed25519_consensus::{SigningKey, VerificationKey};
use protobuf::CodedInputStream;

use crate::result::{Result, Error};
use crate::proto_rust;
use crate::peer::{
        connection::*,
        encryption::*
};
use proto_rust::signed_authentication_message::SignedAuthenticationMessage;

const MESSAGE_EPHEMERAL_PUBLIC_SIZE: usize = 35;

pub use write_local_ephemeral_public::write_local_ephemeral_public;
pub use read_remote_ephemeral_public::read_remote_ephemeral_public;
pub use make_encryption_keys::make_encryption_keys;
pub use make_authentication_challenge_code::make_authentication_challenge_code;
pub use read_write_authentication::read_write_authentication;

mod write_local_ephemeral_public {
        use super::*;

        pub fn write_local_ephemeral_public(
                connection: &mut Connection,
                local_ephemeral_public: &EphemeralPublic
        ) -> Result<()>{
                let mut message = Vec::with_capacity(MESSAGE_EPHEMERAL_PUBLIC_SIZE);

                message.push((MESSAGE_EPHEMERAL_PUBLIC_SIZE - 1) as u8);
                CodedOutputStream::new(&mut message)
                        .write_bytes(1, local_ephemeral_public.as_bytes())
                        .map_err(Error::ProtoWriteFailed)?;

                connection.write_all(&message)?;

                Ok(())
        }

        #[cfg(test)]
        mod tests{
                use rand_core::OsRng;
                use x25519_dalek::EphemeralSecret;
                use super::*;

                #[test]
                pub fn write_local_ephemeral_public_success() {
                        let mut connection = Connection::Fake(ConnectionFake::default());
                        let local_ephemeral_public = EphemeralPublic::from(
                                &EphemeralSecret::random_from_rng(OsRng));

                        write_local_ephemeral_public(
                                &mut connection,
                                &local_ephemeral_public
                        ).expect("Failed to write local ephemeral public");

                        let message_sent = &connection.connection_fake().remote_to_read;
                        assert_eq!(message_sent.len(), MESSAGE_EPHEMERAL_PUBLIC_SIZE);
                        assert_eq!(
                                message_sent[..3],
                                [(MESSAGE_EPHEMERAL_PUBLIC_SIZE - 1) as u8, 0x0a, 0x20]
                        );
                        assert_eq!(
                                *local_ephemeral_public.as_bytes(),
                                message_sent[3..MESSAGE_EPHEMERAL_PUBLIC_SIZE]
                        );
                }
        }
}

mod read_remote_ephemeral_public {
        use super::*;

        pub fn read_remote_ephemeral_public(connection: &mut Connection) -> Result<EphemeralPublic>{
                let mut message = [0u8; MESSAGE_EPHEMERAL_PUBLIC_SIZE];
                connection.read_exact(&mut message)?;

                parse_message_to_ephemeral_public(&message)
        }

        fn parse_message_to_ephemeral_public(message: &[u8; MESSAGE_EPHEMERAL_PUBLIC_SIZE]) -> Result<EphemeralPublic>{
                let message_size = message[0];

                let is_annonced_message_size_correct = message_size as usize == MESSAGE_EPHEMERAL_PUBLIC_SIZE - 1;
                if !is_annonced_message_size_correct {
                        return Err(Error::MessageEphemeralPublicBadSize(message.to_vec()));
                }

                let mut remote_ephemeral_public = [0u8;32];
                remote_ephemeral_public.copy_from_slice(
                        message.get(3..MESSAGE_EPHEMERAL_PUBLIC_SIZE)
                                .expect("35 - 3 = 32"));

                Ok(remote_ephemeral_public.into())
        }

        #[cfg(test)]
        mod tests{
                use super::*;

                #[test]
                pub fn read_remote_ephemeral_public_success() {
                        let mut connection = Connection::Fake(ConnectionFake::default());

                        let mut fake_message = [1u8; MESSAGE_EPHEMERAL_PUBLIC_SIZE];
                        fake_message[0] = (MESSAGE_EPHEMERAL_PUBLIC_SIZE - 1) as u8;
                        fake_message[1] = 0x0a;
                        fake_message[2] = 0x20;

                        connection.connection_fake_mut().local_to_read = Vec::from(fake_message);

                        let remote_ephemeral_public = read_remote_ephemeral_public(&mut connection)
                                .expect("Failed to read remote ephemeral public");

                        assert_eq!(remote_ephemeral_public.as_bytes(), &([1u8; 32]));
                }
        }
}

mod make_encryption_keys {
        use super::*;

        pub fn make_encryption_keys(
                is_local_ephemeral_public_smaller_than_remote: bool,
                shared_secret: &SharedSecret
        ) -> Result<Encryption> {
                let chacha_encryption_keys = ChaChaEncryptionKeys::new(
                        shared_secret,
                        is_local_ephemeral_public_smaller_than_remote
                );

                Ok(Encryption{
                        reader_key: chacha_encryption_keys.reader,
                        writer_key: chacha_encryption_keys.writer,
                        write_nonce: 0,
                        read_nonce: 0,
                })
        }

        struct ChaChaEncryptionKeys{
                reader: ChaCha20Poly1305,
                writer: ChaCha20Poly1305,
        }
        impl ChaChaEncryptionKeys{
                pub fn new(shared_secret: &SharedSecret,
                           is_local_ephemeral_public_smaller_than_remote: bool
                ) -> Self {
                        let mut hkdf_sha256 = [0u8; 64];
                        Hkdf::<Sha256>::new(
                                None,
                                shared_secret.as_bytes())
                                .expand(b"TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN", &mut hkdf_sha256)
                                .expect("64 < x * 255");
                        let (reader,
                                writer): ([u8;32], [u8;32]) = match is_local_ephemeral_public_smaller_than_remote {
                                true =>(
                                        hkdf_sha256
                                                .get(..32)
                                                .expect("size 96")
                                                .try_into()
                                                .expect("size = 32"),
                                        hkdf_sha256
                                                .get(32..64)
                                                .expect("size 96")
                                                .try_into()
                                                .expect("size = 32"),
                                ),
                                false => (
                                        hkdf_sha256
                                                .get(32..64)
                                                .expect("size 96")
                                                .try_into()
                                                .expect("size = 32"),
                                        hkdf_sha256
                                                .get(..32)
                                                .expect("size 96")
                                                .try_into()
                                                .expect("size = 32"),
                                )
                        };

                        ChaChaEncryptionKeys {
                                reader: ChaCha20Poly1305::new(&reader.into()),
                                writer: ChaCha20Poly1305::new(&writer.into()),
                        }
                }
        }

        #[cfg(test)]
        mod tests {
                use rand_core::OsRng;
                use x25519_dalek::{PublicKey, StaticSecret};
                use super::*;

                #[test]
                pub fn make_encryption_keys_success() {
                        make_encryption_keys(
                                true,
                                &StaticSecret::random_from_rng(OsRng)
                                        .diffie_hellman(&PublicKey::from([8u8;32]))
                        ).expect("Failed to make encryption keys");
                }
        }
}

mod make_authentication_challenge_code{
        use super::*;

        pub fn make_authentication_challenge_code(
                local_ephemeral_public: &EphemeralPublic,
                remote_ephemeral_public: &EphemeralPublic,
                shared_secret: &SharedSecret
        ) -> [u8; 32]{
                let is_local_ephemeral_public_smaller_than_remote =
                        local_ephemeral_public.as_bytes() < remote_ephemeral_public.as_bytes();

                let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");

                let (smaller_ephemeral_public,
                        bigger_ephemeral_public) = match is_local_ephemeral_public_smaller_than_remote {
                        true => (local_ephemeral_public, remote_ephemeral_public),
                        false => (remote_ephemeral_public, local_ephemeral_public)
                };

                transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", smaller_ephemeral_public.as_bytes());
                transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", bigger_ephemeral_public.as_bytes());
                transcript.append_message(b"DH_SECRET", shared_secret.as_bytes());

                let mut message_authentication_code = [0u8; 32];
                transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut message_authentication_code);

                message_authentication_code
        }

        #[cfg(test)]
        mod tests {
                use super::*;
                use rand_core::OsRng;
                use x25519_dalek::EphemeralSecret;

                #[test]
                pub fn make_authentication_challenge_code_success(){
                        let local_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
                        let local_ephemeral_public = EphemeralPublic::from(&local_ephemeral_secret);
                        let remote_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
                        let remote_ephemeral_public = EphemeralPublic::from(&remote_ephemeral_secret);

                        let local_shared_secret = local_ephemeral_secret
                                .diffie_hellman(&remote_ephemeral_public);
                        let remote_shared_secret = remote_ephemeral_secret
                                .diffie_hellman(&local_ephemeral_public);

                        let local_challenge = make_authentication_challenge_code(
                                &local_ephemeral_public, &remote_ephemeral_public, &local_shared_secret);
                        let remote_challenge = make_authentication_challenge_code(
                                &remote_ephemeral_public, &local_ephemeral_public, &remote_shared_secret);

                        // Crypto is really magic \(o.O)/
                        assert_eq!(local_challenge, remote_challenge);
                }

        }

}

mod read_write_authentication{
        use super::*;

        pub fn read_write_authentication(
                remote_address: &Option<[u8; 20]>,
                signing_key: &SigningKey,
                authentication_code: &[u8;32],
                connection: &mut Connection,
                encryption: &mut Encryption
        ) -> Result<()> {

                let signed_authentication_message = make_signed_authentication_message(
                        signing_key,
                        authentication_code
                )?;

                connection.write_all_encrypted(
                        signed_authentication_message.as_slice(),
                        &encryption.writer_key,
                        &mut encryption.write_nonce
                )?;

                let remote_signed_authentication_message =
                        read_signed_authentication_message(connection, encryption)?;

                check_signed_authentication_message(
                        remote_address,
                        &remote_signed_authentication_message,
                        authentication_code
                )
        }

        fn make_signed_authentication_message(
                signing_key: &SigningKey,
                authentication_code: &[u8;32],
        ) -> Result<Vec<u8>>{
                let signed_authentication_code = signing_key.sign(authentication_code);

                let mut signed_authentication_message = SignedAuthenticationMessage::new();

                signed_authentication_message.signed_authentication = signed_authentication_code
                        .to_bytes()
                        .to_vec();

                signed_authentication_message.verification_key
                        .mut_or_insert_default()
                        .set_ed25519(
                                signing_key.verification_key().as_bytes().to_vec()
                        );

                signed_authentication_message
                        .write_length_delimited_to_bytes()
                        .map_err(Error::ProtoWriteFailed)
        }

        fn read_signed_authentication_message(
                connection: &mut Connection,
                encryption: &mut Encryption
        ) -> Result<SignedAuthenticationMessage>{
                let remote_signed_authentication_message = connection
                        .read_next_message_encrypted(
                                &encryption.reader_key,
                                &mut encryption.read_nonce
                        )?;

                let mut coded_input_stream = CodedInputStream::from_bytes(
                        remote_signed_authentication_message.as_slice());
                coded_input_stream.read_uint32().map_err(Error::ProtoReadFailed)?;

                SignedAuthenticationMessage::parse_from_reader(&mut coded_input_stream)
                        .map_err(Error::ProtoReadFailed)
        }

        fn check_signed_authentication_message(
                remote_address: &Option<[u8; 20]>,
                signed_authentication_message: &SignedAuthenticationMessage,
                authentication_code: &[u8;32],
        ) -> Result<()>{
                let remote_verification = signed_authentication_message
                        .verification_key
                        .as_ref()
                        .ok_or(Error::RemoteVerificationKeyMissing)?;
                if !remote_verification.has_ed25519(){
                        return Err(Error::RemoteVerificationKeyMissing);
                }
                let remote_verification = VerificationKey::try_from(
                        remote_verification.ed25519()
                ).map_err(|_| Error::SignedAuthenticationMessageMalformed)?;

                remote_verification.verify(
                        &signed_authentication_message
                                .signed_authentication
                                .as_slice()
                                .try_into()
                                .map_err(|_| Error::SignedAuthenticationMessageMalformed)?,
                        authentication_code
                ).map_err(Error::RemotePeerSignatureVerificationFailed)?;

                let mut hasher = Sha256::new();
                hasher.update(remote_verification.as_bytes());
                let address_received = &hasher.finalize()[..20];

                match remote_address {
                        Some(remote_address) if remote_address == address_received =>
                                Ok(()),
                        Some(remote_address) =>
                                Err(Error::RemoteAddressDoesntMatch(
                                        remote_address.to_vec(),
                                        address_received.to_vec()
                                )),
                        None =>
                                Ok(()),
                }
        }

        #[cfg(test)]
        mod tests {
                use super::*;
                use rand_core::OsRng;

                #[test]
                pub fn make_signed_authentication_message_success() {
                        let local_signing = SigningKey::new(OsRng);
                        let authentication_code = [8u8;32];

                        let signed_authentication_message = make_signed_authentication_message(
                                &local_signing,
                                &authentication_code
                        ).expect("Failed to make signed authentication message");

                        let signed_authentication_message =
                                SignedAuthenticationMessage::parse_from_bytes(
                                        &signed_authentication_message[1..]
                                ).expect("Failed to parse proto signed authentication message");

                        local_signing
                                .verification_key()
                                .verify(
                                        &signed_authentication_message
                                                .signed_authentication
                                                .as_slice()
                                                .try_into()
                                                .expect("Failed to make signature"),
                                        &authentication_code
                                ).expect("Failed to verify signature");
                }

                #[test]
                pub fn read_check_signed_authentication_message_success(){
                        let remote_signing = SigningKey::new(OsRng);
                        let authentication_code = [8u8;32];
                        let mut hasher = Sha256::new();
                        hasher.update(remote_signing.verification_key().as_bytes());
                        let remote_address = &hasher.finalize()[..20];

                        let mut local_encryption = Encryption {
                                reader_key: ChaCha20Poly1305::new(&[42u8; 32].into()),
                                writer_key: ChaCha20Poly1305::new(&[41u8; 32].into()),
                                write_nonce: 0,
                                read_nonce: 0,
                        };
                        let mut remote_encryption = Encryption {
                                reader_key: local_encryption.writer_key.clone(),
                                writer_key: local_encryption.reader_key.clone(),
                                write_nonce: 0,
                                read_nonce: 0,
                        };

                        let mut local_connection = Connection::Fake(ConnectionFake::default());
                        let mut remote_connection = Connection::Fake(ConnectionFake::default());

                        let signed_authentication_message = make_signed_authentication_message(
                                &remote_signing,
                                &authentication_code
                        ).expect("Failed to make signed authentication message");

                        remote_connection.write_all_encrypted(
                                &signed_authentication_message,
                                &remote_encryption.writer_key,
                                &mut remote_encryption.write_nonce
                        ).expect("Failed to write signed authentication message");
                        local_connection.connection_fake_mut().local_to_read = remote_connection
                                .connection_fake()
                                .remote_to_read
                                .clone();

                        let signed_authentication_message = read_signed_authentication_message(
                                &mut local_connection,
                                &mut local_encryption
                        ).expect("Failed to read signed authentication message");

                        check_signed_authentication_message(
                                &Some(remote_address.try_into().expect("Fixed size")),
                                &signed_authentication_message,
                                &authentication_code
                        ).expect("Failed to check signed authentication message");
                }
        }
}