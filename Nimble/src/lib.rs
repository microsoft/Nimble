#![feature(test)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

extern crate digest;
extern crate ed25519_dalek;
extern crate rand;
extern crate sha3;

mod endorser;
mod errors;
