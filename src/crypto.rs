use curve25519_dalek::{
        MontgomeryPoint,
        Scalar,
        constants::{X25519_BASEPOINT}
};
use rand_core::OsRng;

pub fn make_private_public_key_ed25519() -> (Scalar, MontgomeryPoint) {
        let private = Scalar::random(&mut OsRng);
        let public = X25519_BASEPOINT * private;
        (private, public)
}

