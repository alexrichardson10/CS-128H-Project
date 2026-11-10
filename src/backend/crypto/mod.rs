//! Pretty much all of these modules WILL create incorrect behavior in response to bad
//! inputs. Input validation should be handled by the caller. I'd be surprised if these
//! can panic, though. So that's nice I guess.

pub mod hkdf;
pub mod diffie_hellman;
#[cfg(test)]
mod tests;
pub mod tls;
pub mod quic;
pub mod aead_aes_128_gcm;
pub mod aes_128_ecb;