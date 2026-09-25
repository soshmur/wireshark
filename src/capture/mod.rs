//! Stage 1: obtaining raw frames. Everything here is parsing-free.

pub mod device;
pub mod file;
pub mod frame;
pub mod preflight;
pub mod thread;

pub use device::Device;
pub use frame::{RawFrame, Timestamp};
pub use preflight::Preflight;
pub use thread::{Capture, CaptureConfig, StatsSnapshot};
