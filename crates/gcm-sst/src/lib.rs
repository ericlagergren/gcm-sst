//! GCM-SST

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod gcm;
mod rust_crypto;
mod tests;

pub use gcm::*;
