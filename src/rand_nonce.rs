use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use secrecy::{ExposeSecret, Secret};

pub struct RandomNonce {
    pub r_public: RistrettoPoint,
    pub(crate) r_private: Secret<Scalar>,
}

use std::fmt;
impl fmt::Debug for RandomNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Format the KeyPair struct without including private_key
        write!(f, "RandomNonce {{ r_public: {:?} }}", self.r_public)
    }
}

impl Clone for RandomNonce {
    fn clone(&self) -> Self {
        let r_public_clone = self.r_public;
        let r_private_clone = Secret::new(*self.r_private.expose_secret());

        RandomNonce {
            r_public: r_public_clone,
            r_private: r_private_clone,
        }
    }
}

impl RandomNonce {
    pub fn new_rand() -> RandomNonce {
        let mut rng = rand::thread_rng();
        let r_private = Secret::new(Scalar::random(&mut rng));
        let r_public: RistrettoPoint = r_private.expose_secret() * RISTRETTO_BASEPOINT_POINT;
        RandomNonce {
            r_private,
            r_public,
        }
    }
}
