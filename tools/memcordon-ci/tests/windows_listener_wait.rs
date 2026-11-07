use memcordon_ci::{
    CiError,
    windows_listener_wait::{self as wait, Failure, Identity, Owner, Publication},
    work_outcome::WorkOutcome,
};
use std::{
    io,
    time::{Duration, Instant},
};
const ORIGINAL: Identity = Identity {
    pid: 24368,
    birth: 134380039621544997,
};
fn owner(status: Option<u32>) -> io::Result<Owner> {
    Ok(Owner {
        identity: ORIGINAL,
        exit_status: status,
    })
}
fn published() -> io::Result<Option<Publication>> {
    Ok(Some(Publication {
        pid: ORIGINAL.pid,
        value: 40000_u16.to_le_bytes().to_vec(),
    }))
}
fn failure(error: &io::Error) -> &Failure {
    error.get_ref().unwrap().downcast_ref().unwrap()
}

#[test]
fn original_exit_wins_immediately_even_without_transcript_or_after_publication_race() {
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(60);
    let error = wait::poll(
        ORIGINAL,
        cutoff,
        || now,
        || owner(Some(101)),
        || panic!("retired root must not wait for transcript"),
    )
    .unwrap_err();
    assert_eq!(
        failure(&error),
        &Failure::Retired {
            identity: ORIGINAL,
            status: 101
        }
    );
    let mut queried = 0;
    let error = wait::poll(
        ORIGINAL,
        cutoff,
        || now,
        || {
            queried += 1;
            owner((queried == 2).then_some(101))
        },
        published,
    )
    .unwrap_err();
    assert_eq!(queried, 2);
    assert_eq!(
        failure(&error),
        &Failure::Retired {
            identity: ORIGINAL,
            status: 101
        }
    );
    // A still-live, silent child remains pending; its next observed exit does
    // not consume the remaining sixty-second publication allowance.
    assert_eq!(
        wait::poll(ORIGINAL, cutoff, || now, || owner(None), || Ok(None)).unwrap(),
        None
    );
    let error = wait::poll(
        ORIGINAL,
        cutoff,
        || now + Duration::from_secs(1),
        || owner(Some(101)),
        || Ok(None),
    )
    .unwrap_err();
    assert_eq!(
        failure(&error),
        &Failure::Retired {
            identity: ORIGINAL,
            status: 101
        }
    );
}
#[test]
fn publication_requires_same_live_owner_valid_bytes_and_original_unexpired_cutoff() {
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(60);
    assert_eq!(
        wait::poll(ORIGINAL, cutoff, || now, || owner(None), published).unwrap(),
        Some(40000)
    );
    let error = wait::poll(
        ORIGINAL,
        cutoff,
        || cutoff,
        || owner(None),
        || panic!("expired cutoff cannot admit publication"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let mut checks = 0;
    let error = wait::poll(
        ORIGINAL,
        cutoff,
        || {
            checks += 1;
            if checks == 1 { now } else { cutoff }
        },
        || owner(None),
        published,
    )
    .unwrap_err();
    assert_eq!(failure(&error), &Failure::Deadline);
    for identity in [
        Identity {
            pid: ORIGINAL.pid + 1,
            ..ORIGINAL
        },
        Identity {
            birth: ORIGINAL.birth + 1,
            ..ORIGINAL
        },
    ] {
        let error = wait::poll(
            ORIGINAL,
            cutoff,
            || now,
            || {
                Ok(Owner {
                    identity,
                    exit_status: None,
                })
            },
            || panic!("foreign hold cannot admit transcript"),
        )
        .unwrap_err();
        assert_eq!(failure(&error), &Failure::IdentityMismatch);
    }
    for publication in [
        Publication {
            pid: ORIGINAL.pid + 1,
            value: vec![1, 2],
        },
        Publication {
            pid: ORIGINAL.pid,
            value: vec![1],
        },
        Publication {
            pid: ORIGINAL.pid,
            value: vec![0, 0],
        },
    ] {
        let error = wait::poll(
            ORIGINAL,
            cutoff,
            || now,
            || owner(None),
            || Ok(Some(publication)),
        )
        .unwrap_err();
        assert_eq!(failure(&error), &Failure::PublicationMismatch);
    }
}
#[test]
fn only_missing_transcripts_are_pending_and_native_query_or_read_errors_keep_their_causes() {
    assert!(
        wait::transcript_bytes(Err(io::Error::new(io::ErrorKind::NotFound, "pending")))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        wait::transcript_bytes(Ok(vec![0, 255])).unwrap(),
        Some(vec![0, 255])
    );
    assert_eq!(
        wait::transcript_bytes(Err(io::Error::from_raw_os_error(13)))
            .unwrap_err()
            .raw_os_error(),
        Some(13)
    );
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(60);
    let error = wait::poll(
        ORIGINAL,
        cutoff,
        || now,
        || Err(io::Error::from_raw_os_error(5)),
        || panic!("failed held query cannot read publication"),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(5));
    let error = wait::poll(
        ORIGINAL,
        cutoff,
        || now,
        || owner(None),
        || {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed existing transcript",
            ))
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "malformed existing transcript");
}
#[test]
fn original_retirement_cause_survives_real_error_composition_with_secondary_cleanup_failure() {
    let now = Instant::now();
    let original = wait::poll(
        ORIGINAL,
        now + Duration::from_secs(60),
        || now,
        || owner(Some(101)),
        published,
    )
    .unwrap_err();
    let error = WorkOutcome::<()>::from_result(Err(CiError::Io(original)))
        .postcondition(Err(CiError::Io(io::Error::from_raw_os_error(13))))
        .into_result()
        .unwrap_err();
    let source = match &error {
        CiError::OwnedWork { source, .. } => source.as_ref(),
        error => error,
    };
    let CiError::LaneFailures { primary, secondary } = source else {
        panic!("typed primary and secondary must remain")
    };
    let CiError::Io(primary) = primary.as_ref() else {
        panic!("original listener I/O cause missing")
    };
    assert_eq!(
        failure(primary),
        &Failure::Retired {
            identity: ORIGINAL,
            status: 101
        }
    );
    assert!(matches!(secondary.as_ref(),CiError::Io(error) if error.raw_os_error()==Some(13)));
}

#[test]
fn only_exact_released_retired_prefix_without_recipient_or_release_debt_can_settle_naturally() {
    let stages = [
        "started",
        "native-argv-observed",
        "sentinel-handles-excluded",
        "token-envelope",
        "controller-released",
    ];
    let retired = Failure::Retired {
        identity: ORIGINAL,
        status: 2,
    };
    let observed = || Owner {
        identity: ORIGINAL,
        exit_status: Some(2),
    };
    assert_eq!(
        wait::application_end(
            ORIGINAL,
            observed(),
            &retired,
            true,
            &stages,
            Some(0),
            Some(false)
        ),
        Some(wait::ApplicationEnd {
            identity: ORIGINAL,
            status: 2
        })
    );
    for (recipients, release) in [
        (None, Some(false)),
        (Some(1), Some(false)),
        (Some(0), None),
        (Some(0), Some(true)),
    ] {
        assert!(
            wait::application_end(
                ORIGINAL,
                observed(),
                &retired,
                true,
                &stages,
                recipients,
                release
            )
            .is_none()
        );
    }
    assert!(
        wait::application_end(
            ORIGINAL,
            observed(),
            &retired,
            false,
            &stages,
            Some(0),
            Some(false)
        )
        .is_none()
    );
    for status in [None, Some(0), Some(3)] {
        assert!(
            wait::application_end(
                ORIGINAL,
                Owner {
                    identity: ORIGINAL,
                    exit_status: status
                },
                &retired,
                true,
                &stages,
                Some(0),
                Some(false)
            )
            .is_none()
        );
    }
    for identity in [
        Identity {
            pid: ORIGINAL.pid + 1,
            ..ORIGINAL
        },
        Identity {
            birth: ORIGINAL.birth + 1,
            ..ORIGINAL
        },
    ] {
        assert!(
            wait::application_end(
                ORIGINAL,
                Owner {
                    identity,
                    exit_status: Some(2)
                },
                &retired,
                true,
                &stages,
                Some(0),
                Some(false)
            )
            .is_none()
        );
    }
    for failure in [
        Failure::IdentityMismatch,
        Failure::PublicationMismatch,
        Failure::Deadline,
        Failure::Retired {
            identity: Identity {
                birth: ORIGINAL.birth + 1,
                ..ORIGINAL
            },
            status: 2,
        },
    ] {
        assert!(
            wait::application_end(
                ORIGINAL,
                observed(),
                &failure,
                true,
                &stages,
                Some(0),
                Some(false)
            )
            .is_none()
        );
    }
    let mut later = stages.to_vec();
    later.push("tcp-listener-owned");
    assert!(
        wait::application_end(
            ORIGINAL,
            observed(),
            &retired,
            true,
            &later,
            Some(0),
            Some(false)
        )
        .is_none()
    );
    assert!(
        wait::application_end(
            ORIGINAL,
            observed(),
            &retired,
            true,
            &stages[..stages.len() - 1],
            Some(0),
            Some(false)
        )
        .is_none()
    );
}
