#[path = "../src/release/linux_image_custody_diagnostic.rs"]
mod diagnostic;

use diagnostic::{NativeCheck, Observation, Phase, failure};
use std::{fmt, io, time::Duration};

#[test]
fn child_image_context_retains_original_operands_and_source_without_formatting_it() {
    use diagnostic::{ImageCheck, ImageOperand, image_failure};
    struct Sensitive;
    impl fmt::Display for Sensitive {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("private cause must not be rendered")
        }
    }
    impl fmt::Debug for Sensitive {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(self, f)
        }
    }
    impl std::error::Error for Sensitive {}
    let checks = [
        ImageCheck::Metadata {
            operand: ImageOperand::Child,
        },
        ImageCheck::Metadata {
            operand: ImageOperand::HeldDriver,
        },
        ImageCheck::DescriptorFlags {
            operand: ImageOperand::Child,
        },
        ImageCheck::DescriptorFlags {
            operand: ImageOperand::HeldDriver,
        },
        ImageCheck::Capability {
            operand: ImageOperand::Child,
            is_file: false,
            is_directory: false,
            flags: u32::MAX,
        },
        ImageCheck::Capability {
            operand: ImageOperand::HeldDriver,
            is_file: true,
            is_directory: false,
            flags: 1,
        },
        ImageCheck::IdentityMismatch {
            child_device: u64::MAX,
            child_inode: 17,
            held_device: 18,
            held_inode: u64::MAX,
        },
    ];
    let mut texts = std::collections::BTreeSet::new();
    for check in checks {
        let inner = image_failure(io::Error::new(io::ErrorKind::InvalidData, Sensitive), check);
        let error = failure(
            inner,
            Observation {
                phase: Phase::CheckChildImageIdentity,
                elapsed: Duration::MAX,
                completed: 0,
                shards: 1,
                last_shard_slots: Some(0),
            },
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let text = error.to_string();
        assert!(text.len() < 2048 && text.contains("phase=CheckChildImageIdentity"));
        assert!(format!("{error:?}").contains("child-image="));
        let inner = error
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        let original = inner
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert!(original.get_ref().unwrap().is::<Sensitive>());
        texts.insert(text);
    }
    assert_eq!(texts.len(), checks.len());
    assert!(texts.iter().any(|text|text.contains("child-device=18446744073709551615; child-inode=17; held-device=18; held-inode=18446744073709551615")));
    let error = failure(
        image_failure(
            io::Error::from_raw_os_error(9),
            ImageCheck::DescriptorFlags {
                operand: ImageOperand::HeldDriver,
            },
        ),
        Observation {
            phase: Phase::CheckChildImageIdentity,
            elapsed: Duration::ZERO,
            completed: 0,
            shards: 1,
            last_shard_slots: Some(0),
        },
    );
    assert!(error.to_string().contains("original-raw-os-error=Some(9)"));
    let inner = error
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    let original = inner
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(original.raw_os_error(), Some(9));
}

#[test]
fn admission_error_preserves_initiating_kind_code_and_source_without_rendering_sensitive_cause() {
    struct Sensitive;
    impl fmt::Display for Sensitive {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("arbitrary source formatting must never run")
        }
    }
    impl fmt::Debug for Sensitive {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(self, f)
        }
    }
    impl std::error::Error for Sensitive {}
    let original = io::Error::new(io::ErrorKind::TimedOut, Sensitive);
    let error = failure(
        original,
        Observation {
            phase: Phase::ReceiveAck,
            elapsed: Duration::from_micros(7),
            completed: 128,
            shards: 2,
            last_shard_slots: Some(0),
        },
    );
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let text = error.to_string();
    assert!(text.starts_with("original-kind=TimedOut; original-raw-os-error=None;"));
    assert!(text.contains(
        "phase=ReceiveAck; elapsed-micros=7; completed=128; shards=2; last-shard-slots=Some(0)"
    ));
    assert!(format!("{error:?}").contains("phase=ReceiveAck"));
    let source = error
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(source.kind(), io::ErrorKind::TimedOut);
    assert!(source.get_ref().unwrap().is::<Sensitive>());

    let error = failure(
        io::Error::from_raw_os_error(24),
        Observation {
            phase: Phase::Spawn,
            elapsed: Duration::MAX,
            completed: usize::MAX,
            shards: usize::MAX,
            last_shard_slots: Some(usize::MAX),
        },
    );
    assert!(error.to_string().contains("original-raw-os-error=Some(24)"));
    let original = error
        .get_ref()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<io::Error>()
        .unwrap();
    assert_eq!(original.raw_os_error(), Some(24));
    assert_eq!(error.kind(), original.kind());
}

#[test]
fn every_closed_boundary_has_a_distinct_fixed_diagnostic_without_new_native_queries() {
    let phases = [
        Phase::ValidateAdmission,
        Phase::ReserveDescriptors,
        Phase::QualifyDriver,
        Phase::HashOriginalDriver,
        Phase::PrepareNonce,
        Phase::ObserveParent,
        Phase::ExportCutoffs,
        Phase::CreateSocket,
        Phase::Spawn,
        Phase::ObserveChildIdentity,
        Phase::OpenChildImage,
        Phase::CheckChildImageIdentity,
        Phase::HashChildImage,
        Phase::ReceiveHello,
        Phase::DecodeHello,
        Phase::CheckHello,
        Phase::CheckCutoff(NativeCheck::Other),
        Phase::ObserveNativeExit(NativeCheck::Hello),
        Phase::ObserveNativeBirth(NativeCheck::BeforeSend),
        Phase::ObserveNativeBirth(NativeCheck::AfterAck),
        Phase::PrepareBinding,
        Phase::EncodeAdmission,
        Phase::SendAdmission,
        Phase::ReceiveAck,
        Phase::DecodeAck,
        Phase::CheckAck,
        Phase::ReuseLease,
    ];
    let rendered: std::collections::BTreeSet<_> = phases
        .into_iter()
        .map(|phase| {
            failure(
                io::ErrorKind::TimedOut.into(),
                Observation {
                    phase,
                    elapsed: Duration::ZERO,
                    completed: 0,
                    shards: 0,
                    last_shard_slots: None,
                },
            )
            .to_string()
        })
        .collect();
    assert_eq!(rendered.len(), phases.len());
}
