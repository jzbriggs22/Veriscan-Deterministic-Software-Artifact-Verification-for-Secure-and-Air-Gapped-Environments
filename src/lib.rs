/// veriscan_lib — defense-grade artifact verification library.
///
/// All business logic lives in this library crate. The binary (`veriscan`)
/// is a thin CLI wrapper that calls into this library.
pub mod config;
pub mod error;
pub mod evidence;
pub mod orchestrator;
pub mod report;
pub mod stages;
pub mod util;

/// Crate version, injected at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
