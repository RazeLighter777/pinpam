//! Core TPM PIN management primitives.
//!
//! This module exposes a high-level interface for provisioning, removing and
//! validating user PINs that are sealed inside TPM NV storage.

#[macro_use]
extern crate rust_i18n;
i18n!("locales", fallback = "en");

pub mod pinconstants;
pub mod pindata;
pub mod pinerror;
pub mod pinindex;
pub mod pinmanager;
pub mod pinpolicy;
pub mod util;
