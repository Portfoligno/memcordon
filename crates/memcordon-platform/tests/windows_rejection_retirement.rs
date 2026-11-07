#[path = "../../memcordon-core/tests/support/windows_current_frontend_guardian.rs"]
mod frontend_support;
#[path = "../src/sealed/windows_rejection_retirement.rs"]
mod retirement;
use frontend_support::postauthorization as support;

use memcordon_core::*;
use retirement::{RejectionContext, complete_rejection_ack, complete_terminal_ack};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    String::from(DiagnosticSha256::from_bytes(Sha256::digest(bytes).into()))
}

fn fixture(required: bool) -> (PublicProviderBindingV1, WindowsProviderResponseV4) {
    let historical = support::rejection();
    let mut rejection = WindowsProviderRejectionV3 {
        schema_version: 3,
        provider_failure: historical.provider_failure.clone(),
        guardian_causal_receipt: historical.guardian_causal_receipt.clone(),
        code: historical.code.clone(),
        phase: historical.phase,
        detail: historical.detail.clone(),
        os_code: historical.os_code,
        loader_qualification: historical.loader_qualification.clone(),
        target_created: false,
        target_released: false,
        cleanup_attempted: historical.cleanup_attempted,
        restart_safety: historical.restart_safety.clone(),
        disposition: WindowsProviderRejectionDispositionV3::Preauthorization {
            terminal_ack_required: required,
        },
    };
    let provider = rejection
        .provider_failure
        .as_ref()
        .unwrap()
        .provider_binding
        .clone();
    let receipt = historical.terminal_receipt().unwrap();
    let (attempt_id, nonce, request_sha256) = (
        receipt.attempt_id.clone(),
        receipt.nonce.clone(),
        receipt.request_sha256.clone(),
    );
    rejection.provider_failure = None;
    rejection.code = "MCSEALED-WINDOWS-CERTIFICATION-FAULT".into();
    rejection.phase = BoundarySetupPhase::ResourceVerification;
    rejection.target_created = false;
    rejection.target_released = false;
    rejection.disposition = WindowsProviderRejectionDispositionV3::Preauthorization {
        terminal_ack_required: required,
    };
    assert!(rejection.is_consistent());
    (
        provider,
        WindowsProviderResponseV4::Reject {
            schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
            attempt_id,
            nonce,
            request_sha256,
            rejection,
        },
    )
}

fn context<'a>(
    provider: &'a PublicProviderBindingV1,
    response: &'a WindowsProviderResponseV4,
) -> RejectionContext<'a> {
    let (attempt_id, nonce, request_sha256) = match response {
        WindowsProviderResponseV4::Reject {
            attempt_id,
            nonce,
            request_sha256,
            ..
        } => (attempt_id, nonce, request_sha256),
        WindowsProviderResponseV4::Terminal(receipt) => {
            (&receipt.attempt_id, &receipt.nonce, &receipt.request_sha256)
        }
        _ => unreachable!(),
    };
    RejectionContext {
        attempt_id,
        nonce,
        request_sha256,
        provider,
    }
}

fn primary(context: &RejectionContext<'_>) -> Error {
    let mut error = Error::new(
        ErrorCategory::Setup,
        "ORIGINAL-REJECTION",
        "original stream-create rejection",
    );
    error.provider_association = Some(Box::new(execution_facts::ProviderAttemptAssociationV1 {
        provider: context.provider.clone(),
        attempt_id: DiagnosticSha256::try_from(BoundedText::new(context.attempt_id).unwrap())
            .unwrap(),
        request_sha256: DiagnosticSha256::try_from(
            BoundedText::new(context.request_sha256).unwrap(),
        )
        .unwrap(),
    }));
    error
}

fn retired(context: &RejectionContext<'_>, authority: &str) -> Vec<u8> {
    let proof = WindowsPreauthorizationRetirementProofV1 {
        schema_version: 1,
        attempt_id: context.attempt_id.into(),
        nonce: context.nonce.into(),
        request_sha256: context.request_sha256.into(),
        provider_generation: context.provider.generation.as_str().into(),
        original_boot_id: "boot".into(),
        launch_incarnation: "launch".into(),
        job_identity: "1".repeat(64),
        terminal_response_sha256: authority.into(),
        target_identity: None,
        guardian_identity: None,
        worker_identity: None,
        worker_thread_identity: None,
        frozen_owner_manifest_sha256: None,
        target_created: false,
        authorization_unix_millis: None,
        resume_attempted: false,
        target_released: false,
        cleanup_state: WindowsDurableCleanupStateV1 {
            termination_requested: true,
            active_processes_zero: true,
            guardian_reaped: true,
            final_handles_closed: true,
        },
        recorded_target_and_guardian_extinct: true,
    };
    let confirmation = WindowsTerminalRetiredV2 {
        schema_version: 2,
        attempt_id: context.attempt_id.into(),
        nonce: context.nonce.into(),
        request_sha256: context.request_sha256.into(),
        terminal_response_sha256: authority.into(),
        disposition: WindowsAttemptTerminalDispositionV1::PreauthorizationAbort,
        provider_generation: context.provider.generation.as_str().into(),
        original_boot_id: "boot".into(),
        launch_incarnation: "launch".into(),
        job_identity: "1".repeat(64),
        owner_manifest_sha256: String::new(),
        retirement_proof_sha256: proof.canonical_sha256().unwrap(),
        preauthorization_retirement_proof: Some(proof),
        ledger_generation: "2".repeat(64),
        completion: WindowsRetirementLedgerCompletionV1::RetirementComplete,
    };
    assert!(confirmation.is_consistent_for(
        context.attempt_id,
        context.nonce,
        context.request_sha256,
        authority
    ));
    serde_json::to_vec(&WindowsProviderResponseV4::TerminalRetiredV2(confirmation)).unwrap()
}

fn postauthorization_response() -> (PublicProviderBindingV1, WindowsProviderResponseV4) {
    let (rejection, held, _, _) = frontend_support::fixture();
    let receipt = rejection.terminal_receipt().unwrap();
    let response = WindowsProviderResponseV4::Reject {
        schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
        attempt_id: receipt.attempt_id.clone(),
        nonce: receipt.nonce.clone(),
        request_sha256: receipt.request_sha256.clone(),
        rejection,
    };
    (held.association.provider, response)
}

fn posttarget_retired(response: &WindowsProviderResponseV4, authority: &str) -> Vec<u8> {
    let receipt = match response {
        WindowsProviderResponseV4::Reject { rejection, .. } => {
            rejection.terminal_receipt().unwrap()
        }
        WindowsProviderResponseV4::Terminal(receipt) => receipt,
        _ => unreachable!(),
    };
    let proof = &receipt.retirement_proof;
    let confirmation = WindowsTerminalRetiredV2 {
        schema_version: 2,
        attempt_id: receipt.attempt_id.clone(),
        nonce: receipt.nonce.clone(),
        request_sha256: receipt.request_sha256.clone(),
        terminal_response_sha256: authority.into(),
        disposition: WindowsAttemptTerminalDispositionV1::Posttarget,
        provider_generation: proof.provider_generation.clone(),
        original_boot_id: proof.original_boot_id.clone(),
        launch_incarnation: proof.launch_incarnation.clone(),
        job_identity: proof.job_identity.clone(),
        owner_manifest_sha256: proof.owner_manifest_sha256.clone(),
        retirement_proof_sha256: digest(&serde_json::to_vec(proof).unwrap()),
        preauthorization_retirement_proof: None,
        ledger_generation: "2".repeat(64),
        completion: WindowsRetirementLedgerCompletionV1::RetirementComplete,
    };
    assert!(confirmation.is_consistent_for(
        &receipt.attempt_id,
        &receipt.nonce,
        &receipt.request_sha256,
        authority
    ));
    // Preserve retirement's actual received representation, which is separately
    // hashed and must not be replaced by authority serialization.
    serde_json::to_vec_pretty(&WindowsProviderResponseV4::TerminalRetiredV2(confirmation)).unwrap()
}

#[test]
fn recovery_completion_uses_one_canonical_authority_for_ack_and_delivery_without_expiring_response()
{
    let (provider, response) = postauthorization_response();
    let immutable = response.terminal_authority_json().unwrap();
    let WindowsProviderResponseV4::Reject { rejection, .. } = &response else {
        unreachable!()
    };
    assert!(rejection.provider_failure.is_some());
    assert!(rejection.guardian_causal_receipt.is_some());
    let mut expired = response.clone();
    let WindowsProviderResponseV4::Reject { rejection, .. } = &mut expired else {
        unreachable!()
    };
    rejection.provider_failure = None;
    rejection.guardian_causal_receipt = None;
    assert!(rejection.is_consistent());
    assert_eq!(expired.terminal_authority_json().unwrap(), immutable);
    let WindowsProviderResponseV4::Reject { rejection, .. } = &response else {
        unreachable!()
    };
    let terminal =
        WindowsProviderResponseV4::Terminal(rejection.terminal_receipt().unwrap().clone());
    for response in [&response, &expired, &terminal] {
        let binding = context(&provider, response);
        let raw = serde_json::to_vec_pretty(response).unwrap();
        let before = serde_json::to_vec(response).unwrap();
        let canonical_digest = digest(response.terminal_authority_json().unwrap().as_bytes());
        assert_ne!(digest(&raw), canonical_digest);
        let retired_raw = posttarget_retired(response, &canonical_digest);
        let mut calls = 0;
        let delivery = complete_terminal_ack(response, &binding, |ack_digest| {
            calls += 1;
            assert_eq!(ack_digest, canonical_digest);
            assert_ne!(ack_digest, digest(&raw));
            Ok(retired_raw.clone())
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(delivery.terminal_sha256, canonical_digest);
        assert_eq!(delivery.retired_sha256, digest(&retired_raw));
        assert!(delivery.terminal_validated && delivery.acknowledgement_observed);
        assert_eq!(serde_json::to_vec(response).unwrap(), before);
    }
}

#[test]
fn recovery_completion_rejects_foreign_response_and_retirement_before_marking_delivery() {
    let (provider, response) = postauthorization_response();
    let binding = context(&provider, &response);
    for field in ["attempt_id", "nonce", "request_sha256", "schema_version"] {
        let mut foreign = response.clone();
        let WindowsProviderResponseV4::Reject {
            attempt_id,
            nonce,
            request_sha256,
            schema_version,
            ..
        } = &mut foreign
        else {
            unreachable!()
        };
        match field {
            "attempt_id" => *attempt_id = "9".repeat(64),
            "nonce" => *nonce = "9".repeat(32),
            "request_sha256" => *request_sha256 = "9".repeat(64),
            "schema_version" => *schema_version += 1,
            _ => unreachable!(),
        }
        assert!(
            complete_terminal_ack(&foreign, &binding, |_| panic!(
                "foreign recovery must not ACK"
            ))
            .is_err(),
            "{field}"
        );
    }
    let mut foreign_provider = provider.clone();
    foreign_provider.generation = BoundedText::new("foreign-generation").unwrap();
    let foreign_binding = RejectionContext {
        provider: &foreign_provider,
        ..binding
    };
    assert!(
        complete_terminal_ack(&response, &foreign_binding, |_| panic!(
            "foreign generation must not ACK"
        ))
        .is_err()
    );
    for field in [
        "attempt_id",
        "nonce",
        "request_sha256",
        "provider_generation",
        "terminal_response_sha256",
        "retirement_proof_sha256",
        "ledger_generation",
        "completion",
    ] {
        let result = complete_terminal_ack(&response, &binding, |authority| {
            let mut foreign: serde_json::Value =
                serde_json::from_slice(&posttarget_retired(&response, authority)).unwrap();
            foreign[field] = serde_json::json!(if field == "retirement_proof_sha256"
                || field == "ledger_generation"
            {
                String::new()
            } else {
                "9".repeat(64)
            });
            Ok(serde_json::to_vec(&foreign).unwrap())
        });
        assert!(result.is_err(), "{field}");
    }
    assert!(complete_terminal_ack(&response, &binding, |_| Ok(b"{".to_vec())).is_err());
    assert!(
        complete_terminal_ack(&response, &binding, |_| Err(Box::new(Error::new(
            ErrorCategory::Setup,
            "ACK-FAILED",
            "pipe closed"
        ))))
        .is_err()
    );
}

#[test]
fn early_preauthorization_rejection_acknowledges_exact_authority_and_retains_delivery() {
    let (provider, response) = fixture(true);
    let context = context(&provider, &response);
    let raw = serde_json::to_vec(&response).unwrap();
    let expected = digest(response.terminal_authority_json().unwrap().as_bytes());
    let mut called = false;
    let result =
        complete_rejection_ack(primary(&context), &response, &raw, &context, |authority| {
            called = true;
            assert_eq!(authority, expected);
            Ok(retired(&context, authority))
        });
    assert!(called);
    assert_eq!(result.code, "ORIGINAL-REJECTION");
    assert_eq!(result.message, "original stream-create rejection");
    assert!(!result.target_released);
    let delivery = result.windows_frontend_delivery.unwrap();
    assert!(delivery.acknowledgement_observed);
    assert_eq!(delivery.terminal_sha256, digest(&raw));
    assert_eq!(
        delivery.retired_sha256,
        digest(&retired(&context, &expected))
    );
}

#[test]
fn rejection_without_terminal_obligation_does_not_emit_ack_or_invent_delivery() {
    let (provider, response) = fixture(false);
    let context = context(&provider, &response);
    let result = complete_rejection_ack(
        primary(&context),
        &response,
        &serde_json::to_vec(&response).unwrap(),
        &context,
        |_| panic!("ACK not required"),
    );
    assert!(result.windows_frontend_delivery.is_none());
    assert_eq!(result.message, "original stream-create rejection");
}

#[test]
fn acknowledgment_and_current_delivery_bind_the_same_immutable_native_authority() {
    let (provider, mut response) = fixture(true);
    let immutable = response.terminal_authority_json().unwrap();
    let WindowsProviderResponseV4::Reject { rejection, .. } = &mut response else {
        unreachable!()
    };
    rejection.provider_failure = support::rejection().provider_failure;
    assert!(rejection.is_consistent());
    assert_eq!(response.terminal_authority_json().unwrap(), immutable);
    let context = context(&provider, &response);
    let raw = serde_json::to_vec(&response).unwrap();
    let result =
        complete_rejection_ack(primary(&context), &response, &raw, &context, |authority| {
            assert_eq!(authority, digest(immutable.as_bytes()));
            Ok(retired(&context, authority))
        });
    let delivery = result.windows_frontend_delivery.unwrap();
    assert_ne!(delivery.terminal_sha256, digest(&raw));
    assert_eq!(delivery.terminal_sha256, digest(immutable.as_bytes()));
}

#[test]
fn acknowledgment_failure_preserves_original_rejection_and_rejects_foreign_retirement() {
    let (provider, response) = fixture(true);
    let context = context(&provider, &response);
    let raw = serde_json::to_vec(&response).unwrap();
    let failure = complete_rejection_ack(primary(&context), &response, &raw, &context, |_| {
        Err(Box::new(Error::new(
            ErrorCategory::Setup,
            "ACK-FAILED",
            "pipe closed",
        )))
    });
    assert_eq!(failure.code, "ORIGINAL-REJECTION");
    assert!(failure.message.starts_with(
        "original stream-create rejection; secondary terminal acknowledgment failure:"
    ));
    assert!(failure.message.contains("pipe closed"));
    assert!(failure.windows_frontend_delivery.is_none());
    for field in ["attempt_id", "nonce", "request_sha256", "schema_version"] {
        let mut foreign = response.clone();
        let WindowsProviderResponseV4::Reject {
            schema_version,
            attempt_id,
            nonce,
            request_sha256,
            ..
        } = &mut foreign
        else {
            unreachable!()
        };
        match field {
            "attempt_id" => *attempt_id = "9".repeat(64),
            "nonce" => *nonce = "9".repeat(32),
            "request_sha256" => *request_sha256 = "9".repeat(64),
            "schema_version" => *schema_version += 1,
            _ => unreachable!(),
        }
        let result = complete_rejection_ack(
            primary(&context),
            &foreign,
            &serde_json::to_vec(&foreign).unwrap(),
            &context,
            |_| panic!("foreign response must not emit ACK"),
        );
        assert!(result.windows_frontend_delivery.is_none(), "{field}");
        assert_eq!(result.code, "ORIGINAL-REJECTION");
        assert!(
            result
                .message
                .contains("secondary terminal acknowledgment failure"),
            "{field}"
        );
    }
    for field in [
        "attempt_id",
        "nonce",
        "request_sha256",
        "provider_generation",
        "terminal_response_sha256",
    ] {
        let result =
            complete_rejection_ack(primary(&context), &response, &raw, &context, |authority| {
                let mut foreign: serde_json::Value =
                    serde_json::from_slice(&retired(&context, authority)).unwrap();
                foreign[field] = serde_json::json!("9".repeat(64));
                Ok(serde_json::to_vec(&foreign).unwrap())
            });
        assert!(result.windows_frontend_delivery.is_none(), "{field}");
        assert!(
            result
                .message
                .contains("secondary terminal acknowledgment failure"),
            "{field}"
        );
    }
}
