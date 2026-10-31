//! Factual identity acquisition does not grant target release authorization.
use super::PrivateAttemptPhase;
use memcordon_core::result_v3::ReleaseKnowledgeV3;

pub struct AcquisitionContext {
    pub phase: PrivateAttemptPhase,
    pub release: ReleaseKnowledgeV3,
    pub native_published: bool,
}

#[derive(Clone, Copy)]
pub enum AcquisitionRole {
    NamespaceInit,
    Target,
}

impl AcquisitionContext {
    fn require(&self, phase: PrivateAttemptPhase) -> Result<(), String> {
        if self.phase != phase
            || self.release != ReleaseKnowledgeV3::NotReleased
            || self.native_published
        {
            return Err("native acquisition is outside its original unpublished phase".into());
        }
        Ok(())
    }
}

/// True requests the existing durable write; false is an exact idempotent fact.
pub fn record_identity<I: Eq>(
    role: AcquisitionRole,
    context: &AcquisitionContext,
    intent: bool,
    current: Option<&I>,
    observed: &I,
) -> Result<bool, String> {
    context.require(match role {
        AcquisitionRole::NamespaceInit => PrivateAttemptPhase::BoundaryCreated,
        AcquisitionRole::Target => PrivateAttemptPhase::GuardianReady,
    })?;
    if !intent {
        return Err("native acquisition lacks original allocation intent".into());
    }
    match current {
        None => Ok(true),
        Some(original) if original == observed => Ok(false),
        Some(_) => Err("native acquisition conflicts with original process identity".into()),
    }
}

pub fn require_gated_pair<I: Eq>(
    context: &AcquisitionContext,
    published_init: Option<&I>,
    published_target: Option<&I>,
    observed_init: &I,
    observed_target: &I,
) -> Result<(), String> {
    context.require(PrivateAttemptPhase::GuardianReady)?;
    if published_init != Some(observed_init) || published_target != Some(observed_target) {
        return Err("gated target differs from original acquired process identities".into());
    }
    Ok(())
}
