//! GCM-SST per [draft-mattson-cfrg-aes-gcm-sst-13].
//!
//! [draft-mattson-cfrg-aes-gcm-sst-13]: https://www.ietf.org/archive/id/draft-mattsson-cfrg-aes-gcm-sst-01.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

mod gcm;
mod rust_crypto;
pub mod testing;
mod tests;

pub use gcm::*;
pub use generic_array;
#[cfg(feature = "rust-crypto")]
pub use rust_crypto::CtrGen;
pub use typenum;
