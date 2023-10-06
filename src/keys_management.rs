use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use secrecy::{ExposeSecret, Secret};

pub struct KeyPair {
    pub(crate) private_key: Secret<Scalar>,
    pub public_key: RistrettoPoint,
}

use std::fmt;
impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Format the KeyPair struct without including private_key
        write!(f, "KeyPair {{ public_key: {:?} }}", self.public_key)
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
    pub fn create() -> KeyPair {
        let mut rng = rand::thread_rng();
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

    // TODO
    // pub fn create_from_seed(seed: Scalar) -> KeyPair {
    //     let private_key = Scalar::random(seed);
    //     let ec_point = RISTRETTO_BASEPOINT_POINT;
    //     let public_key: RistrettoPoint = private_key * ec_point;
    //     KeyPair {
    //         private_key,
    //         public_key,
    //     }
    // }
}
