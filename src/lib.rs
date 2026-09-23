//! netscope — a packet capture and analysis application.
//!
//! Pipeline: capture thread -> bounded channel -> dissection workers -> store
//! -> UI snapshot. See DECISIONS.md for the reasoning behind the layout.
//!
//! The library exists so tests, examples and benchmarks can reach the pipeline
//! without the UI; `main.rs` is a thin launcher.

#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub mod app;
pub mod capture;
pub mod config;
pub mod dissect;
pub mod filter;
pub mod pcapng;
pub mod store;
pub mod synthetic;
