use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use secrecy::{ExposeSecret, Secret};

pub struct KeyPair {
    pub(crate) private_key: Secret<Scalar>,
    pub(crate) public_key: RistrettoPoint,
}

use std::fmt;
impl fmt::Debug for KeyPair {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // Format the KeyPair struct without including private_key
        fmt.debug_struct("RandomNonce")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        let private_key_clone = Secret::new(*self.private_key.expose_secret());
        let public_key_clone = self.public_key;

        KeyPair {
            private_key: private_key_clone,
            public_key: public_key_clone,
        }
    }
}

impl KeyPair {
    pub fn create<R>(mut rng: R) -> KeyPair
    where
        R: rand::CryptoRng + rand::RngCore,
    {
        let private_key = Secret::new(Scalar::random(&mut rng));
        let public_key: RistrettoPoint = private_key.expose_secret() * RISTRETTO_BASEPOINT_POINT;
        KeyPair {
            private_key,
            public_key,
        }
    }

    pub fn create_from_private_key(private_key: Secret<Scalar>) -> KeyPair {
        let public_key: RistrettoPoint = private_key.expose_secret() * RISTRETTO_BASEPOINT_POINT;
        KeyPair {
            private_key,
            public_key,
        }
    }

    pub fn get_public_key(self) -> RistrettoPoint {
        self.public_key
    }
}
