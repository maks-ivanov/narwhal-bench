// Copyright (c) The GDEX Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! This feature gets turned on only if gdex-crypto is compiled via MIRAI in a nightly build.
#![cfg_attr(mirai, allow(incomplete_features), feature(const_generics))]
//! ignore from tarpaulin
#![cfg(not(tarpaulin_include))]

//! A library supplying various cryptographic primitives
pub mod compat;
pub mod ed25519;
pub mod error;
pub mod hash;
pub mod multi_ed25519;
pub mod test_utils;
pub mod traits;

#[cfg(mirai)]
mod tags;

pub use self::traits::*;
pub use hash::HashValue;

// Reexport once_cell and serde_name for use in CryptoHasher Derive implementation.
#[doc(hidden)]
pub use once_cell as _once_cell;
#[doc(hidden)]
pub use serde_name as _serde_name;

// We use [formally verified arithmetic](https://crates.io/crates/fiat-crypto)
// in maintained forks of the dalek suite of libraries ({curve, ed,
// x}25519-dalek). This is controlled by a feature in the forked crates
// ('fiat_u64_backend'), which we turn on by default.
#[cfg(not(any(feature = "avx2", feature = "u64", feature = "u32")))]
compile_error!(
    "no dalek arithmetic backend cargo feature enabled! \
     please enable one of: fiat, u64, u32"
);

#[cfg(all(feature = "fiat", feature = "u64"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

#[cfg(all(feature = "fiat", feature = "u32"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

#[cfg(all(feature = "u64", feature = "u32"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

// MIRAI's tag analysis makes use of the incomplete const_generics feature, so the module
// containing the definitions of MIRAI tag types should not get compiled in a release build.
// The code below fails a build of the crate if mirai is on but debug_assertions is not.
#[cfg(all(mirai, not(debug_assertions)))]
compile_error!("MIRAI can only be used to compile the crate in a debug build!");