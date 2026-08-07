use std::time::Duration;

use memcordon_core::{ByteSize, ByteSizeParseError, DeadlinePolicy, DeadlineScope, Policy};

#[test]
fn parses_exact_binary_and_decimal_units() {
    assert_eq!(
        "1.5GiB".parse::<ByteSize>().map(ByteSize::bytes),
        Ok(1_610_612_736)
    );
    assert_eq!("1.1B".parse::<ByteSize>().map(ByteSize::bytes), Ok(2));
    assert_eq!(
        "8000MB".parse::<ByteSize>().map(ByteSize::bytes),
        Ok(8_000_000_000)
    );
}

#[test]
fn policy_constructors_preserve_one_shot_defaults_and_validate_deadlines() {
    assert_eq!(Policy::default().memory.map(ByteSize::bytes), Some(1 << 30));
    assert_eq!(
        Policy::new(ByteSize::from_bytes(7))
            .memory
            .map(ByteSize::bytes),
        Some(7)
    );
    assert_eq!(
        Policy::new(ByteSize::from_bytes(0))
            .memory
            .map(ByteSize::bytes),
        Some(0)
    );
    assert!(Policy::unbounded().memory.is_none());
    assert!(Policy::unbounded().deadline.is_none());
    assert_eq!(Policy::default().command_exit_grace, Duration::ZERO);
    assert_eq!(
        Policy::new(ByteSize::from_bytes(7)).command_exit_grace,
        Duration::ZERO
    );
    assert_eq!(Policy::unbounded().command_exit_grace, Duration::ZERO);
    let immediate = DeadlinePolicy::new(Duration::ZERO, DeadlineScope::Attempt)
        .expect("zero is an immediate deadline");
    assert_eq!(immediate.duration(), Duration::ZERO);
    assert_eq!(immediate.scope(), DeadlineScope::Attempt);
    let immediate_json = serde_json::to_value(immediate).expect("zero deadline JSON");
    let immediate: DeadlinePolicy =
        serde_json::from_value(immediate_json).expect("zero deadline round trip");
    assert_eq!(immediate.duration(), Duration::ZERO);
    assert!(DeadlinePolicy::new(Duration::from_nanos(1), DeadlineScope::Attempt).is_err());
    let deadline = DeadlinePolicy::new(Duration::from_millis(1), DeadlineScope::Supervision)
        .expect("one millisecond is valid");
    assert_eq!(deadline.duration(), Duration::from_millis(1));
    assert_eq!(deadline.scope(), DeadlineScope::Supervision);
    let immediate = Policy::unbounded()
        .with_deadline(Duration::ZERO)
        .expect("an explicit zero deadline remains configured");
    assert_eq!(
        immediate.deadline.map(DeadlinePolicy::duration),
        Some(Duration::ZERO)
    );
}

#[test]
fn accepts_zero_memory_and_rejects_ambiguous_units_and_overflow() {
    assert!(matches!(
        "8G".parse::<ByteSize>(),
        Err(ByteSizeParseError::InvalidUnit(_))
    ));
    for input in ["0", "0B", "0.0GiB"] {
        assert_eq!(
            input.parse::<ByteSize>().map(ByteSize::bytes),
            Ok(0),
            "{input}"
        );
    }
    assert_eq!(
        "999999999999999999999999EB".parse::<ByteSize>(),
        Err(ByteSizeParseError::Overflow)
    );
}
