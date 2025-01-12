//! GCM-SST per [draft-mattson-cfrg-aes-gcm-sst-13].
//!
//! [draft-mattson-cfrg-aes-gcm-sst-13]: https://www.ietf.org/archive/id/draft-mattsson-cfrg-aes-gcm-sst-01.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

mod gcm;
pub mod rust_crypto;
pub mod testing;
mod tests;

pub use gcm::*;
pub use typenum;
