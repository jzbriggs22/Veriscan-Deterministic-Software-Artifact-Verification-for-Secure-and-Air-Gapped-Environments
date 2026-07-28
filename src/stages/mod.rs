/// Pipeline stage modules.
///
/// Stage order is enforced by the orchestrator and cannot be altered at
/// runtime. Each stage receives the artifact path and current pipeline state;
/// it returns its own typed result plus a collection of evidence items.
pub mod acquire;
pub mod bundle;
pub mod hash;
pub mod inspect;
pub mod malware;
pub mod policy;
pub mod reputation;
pub mod signature;
