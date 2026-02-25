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

use crate::evidence::EvidenceItem;

/// Trait all verification stages must implement.
pub trait Stage {
    /// The stage's canonical name, used in evidence and logs.
    fn name(&self) -> &'static str;
}

/// A stage result carries evidence and a stage-specific payload.
#[derive(Debug)]
pub struct StageEvidence {
    pub items: Vec<EvidenceItem>,
}

impl StageEvidence {
    pub fn new() -> Self {
        StageEvidence { items: Vec::new() }
    }

    pub fn push(&mut self, item: EvidenceItem) {
        self.items.push(item);
    }
}

impl Default for StageEvidence {
    fn default() -> Self {
        Self::new()
    }
}
