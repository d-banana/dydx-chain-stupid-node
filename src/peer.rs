mod setup;
mod connection;
mod encryption;

use std::{thread};
use ed25519_consensus::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use crate::result::{Result};
use crate::peer::{
        connection::*,
        encryption::Encryption,
        setup::{
                read_remote_verification::read_remote_verification,
                write_local_verification::write_local_verification,
                make_encryption_keys::make_encryption_keys,
                read_write_authentication::read_write_authentication
        }
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PeerAction {
        Authenticate,
        Listen
}

pub struct Peer {
        pub connection: Connection,
        pub action: PeerAction,
        pub encryption: Option<Encryption>,
}

impl Peer {
        pub fn try_new_tcp(ip: [u8; 4], port: u16) -> Result<Self>{
                Ok(Peer {
                        connection: Connection::Tcp(ConnectionTcp::try_new(ip, port)?),
                        action: PeerAction::Authenticate,
                        encryption: None
                })
        }

        pub fn run(mut self) -> Result<()> {
                thread::spawn(move || -> Result<()> {
                        loop {
                                let result = match self.action {
                                        PeerAction::Authenticate => self.authenticate(),
                                        PeerAction::Listen => {Ok(())}
                                };

                                if let Err(e) = result{
                                        println!("Error: {:?}", e);
                                        return Err(e);
                                }
                        }

                        Ok(())
                });

                Ok(())
        }

        fn authenticate(&mut self) -> Result<()>{
                let local_signing = &SigningKey::new(OsRng);
                let local_verification = &local_signing.verification_key();

                write_local_verification(
                        &mut self.connection,
                        local_verification
                )?;

                let remote_verification = &read_remote_verification(
                        &mut self.connection)?;

                let shared_secret = &StaticSecret::from(
                        *local_signing.as_bytes()
                ).diffie_hellman(&PublicKey::from(*remote_verification.as_bytes()));

                self.encryption = Some(make_encryption_keys(
                        local_verification < remote_verification,
                        shared_secret
                )?);

                read_write_authentication(
                        local_signing,
                        local_verification,
                        remote_verification,
                        shared_secret,
                        &mut self.connection,
                        self.encryption
                                .as_mut()
                                .expect("already set")
                )?;

                self.action = PeerAction::Listen;

                Ok(())
        }
}

impl Default for Peer {
        fn default() -> Self {
                Peer {
                        connection: Connection::Fake(ConnectionFake::default()),
                        action: PeerAction::Authenticate,
                        encryption: Default::default(),
                }
        }
}