//! Kani crate root. `lib.rs` is the BYTE-IDENTICAL atlas-pca source plus one appended line (`mod proofs;`, see build.sh),
//! loaded here as a module so that a crate-level attribute can be set without touching it: the compositional harnesses
//! carry 13 `#[kani::stub]` attributes, which exceed rustc's default macro recursion limit of 128.
#![recursion_limit = "512"]
#![allow(dead_code, unused_imports)]
#[path = "lib.rs"]
mod pca;
