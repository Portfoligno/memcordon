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
    assert!(Policy::unbounded().memory.is_none());
    assert!(Policy::unbounded().deadline.is_none());
    assert!(DeadlinePolicy::new(Duration::ZERO, DeadlineScope::Attempt).is_err());
    assert!(DeadlinePolicy::new(Duration::from_nanos(1), DeadlineScope::Attempt).is_err());
    let deadline = DeadlinePolicy::new(Duration::from_millis(1), DeadlineScope::Supervision)
        .expect("one millisecond is valid");
    assert_eq!(deadline.duration(), Duration::from_millis(1));
    assert_eq!(deadline.scope(), DeadlineScope::Supervision);
    assert!(Policy::unbounded().with_deadline(Duration::ZERO).is_err());
}

#[test]
fn rejects_ambiguous_zero_and_overflow() {
    assert!(matches!(
        "8G".parse::<ByteSize>(),
        Err(ByteSizeParseError::InvalidUnit(_))
    ));
    assert_eq!("0".parse::<ByteSize>(), Err(ByteSizeParseError::Zero));
    assert_eq!(
        "999999999999999999999999EB".parse::<ByteSize>(),
        Err(ByteSizeParseError::Overflow)
    );
}
