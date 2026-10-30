#[path = "private/fixture_namespace_call_marker.rs"]
mod marker;
use marker::*;

const NONCE: &str = "000102030405060708090a0b0c0d0e0f";
const API: u64 = 0x12345678;
fn accept(window: &mut Window, packet: &[u64]) -> Result<Phase, Rejection> {
    window.accept(CODE, 0, true, 3, 5, packet)
}

#[test]
fn strict_order_binds_nonce_owner_and_the_single_call_address() {
    let pre = Packet::pre(NONCE, API).unwrap();
    assert_eq!(pre[2], 0x0706050403020100);
    assert_eq!(pre[3], 0x0f0e0d0c0b0a0908);
    let post = Packet::post(NONCE, API, false, 5).unwrap();
    let mut window = Window::new(3, 5, NONCE).unwrap();
    assert!(accept(&mut window, &post).is_err());
    assert_eq!(window.state, State::AwaitPre);
    assert_eq!(accept(&mut window, &pre).unwrap(), Phase::Pre);
    assert!(accept(&mut window, &pre).is_err());
    assert_eq!(window.state, State::AwaitPost);
    let wrong_api = Packet::post(NONCE, API + 1, false, 5).unwrap();
    assert!(accept(&mut window, &wrong_api).is_err());
    assert!(window.result.is_none());
    assert_eq!(accept(&mut window, &post).unwrap(), Phase::Post);
    assert_eq!(
        window.result,
        Some(CallResult {
            opened: false,
            raw_error: 5
        })
    );
    assert_eq!(window.state, State::Complete);
    assert!(accept(&mut window, &post).is_err());
    assert_eq!(window.result.unwrap().raw_error, 5);
}

#[test]
fn malformed_or_unowned_exceptions_cannot_advance_the_window() {
    let pre = Packet::pre(NONCE, API).unwrap();
    for (code, flags, first, pid, tid) in [
        (CODE + 1, 0, true, 3, 5),
        (CODE | (1 << 28), 0, true, 3, 5),
        (CODE, 1, true, 3, 5),
        (CODE, 2, true, 3, 5),
        (CODE, 0, false, 3, 5),
        (CODE, 0, true, 4, 5),
        (CODE, 0, true, 3, 6),
    ] {
        let mut window = Window::new(3, 5, NONCE).unwrap();
        assert!(window.accept(code, flags, first, pid, tid, &pre).is_err());
        assert_eq!(window.state, State::AwaitPre);
    }
    for (index, value) in [(0, 2), (1, 3), (2, 99), (3, 99), (4, 0), (5, 1), (6, 5)] {
        let mut bad = pre;
        bad[index] = value;
        assert!(accept(&mut Window::new(3, 5, NONCE).unwrap(), &bad).is_err());
    }
    assert!(accept(&mut Window::new(3, 5, NONCE).unwrap(), &pre[..6]).is_err());
    let mut extra = pre.to_vec();
    extra.push(0);
    assert!(accept(&mut Window::new(3, 5, NONCE).unwrap(), &extra).is_err());
}

#[test]
fn post_retains_captured_error_and_rejects_impossible_results() {
    assert!(Packet::pre(&NONCE.to_uppercase(), API).is_err());
    assert!(Packet::pre(&NONCE[..NONCE.len() - 1], API).is_err());
    assert!(Packet::pre(NONCE, 0).is_err());
    assert!(Packet::post(NONCE, API, true, 5).is_err());
    for (opened, error) in [(2, 0), (1, 5), (0, u64::from(u32::MAX) + 1)] {
        let mut window = Window::new(3, 5, NONCE).unwrap();
        accept(&mut window, &Packet::pre(NONCE, API).unwrap()).unwrap();
        let mut packet = Packet::post(NONCE, API, false, 5).unwrap();
        packet[5] = opened;
        packet[6] = error;
        assert!(accept(&mut window, &packet).is_err());
        assert_eq!(window.state, State::AwaitPost);
        assert!(window.result.is_none());
    }
}

#[test]
fn incomplete_and_drifted_windows_never_claim_continuous_coverage() {
    assert_eq!(classify(false, false, false), Coverage::IncompleteWindow);
    assert_eq!(classify(false, true, true), Coverage::IncompleteWindow);
    assert_eq!(classify(true, false, false), Coverage::DriftObserved);
    assert_eq!(classify(true, false, true), Coverage::DriftObserved);
    assert_eq!(classify(true, true, true), Coverage::ObservedProfiledHit);
    assert_eq!(
        classify(true, true, false),
        Coverage::NoHostHitWithIntactPostState
    );
}

#[test]
fn exact_first_rejection_preserves_the_unmodified_window() {
    let pre = Packet::pre(NONCE, API).unwrap();
    for (code, flags, first, pid, tid, reason) in [
        (CODE + 1, 0, true, 3, 5, Rejection::Code),
        (CODE, 1, true, 3, 5, Rejection::Flags),
        (CODE, u32::MAX, false, 3, 5, Rejection::Flags),
        (CODE, 0, false, 3, 5, Rejection::FirstChance),
        (CODE, 0, true, 4, 5, Rejection::OwnerPid),
        (CODE, 0, true, 3, 6, Rejection::OwnerTid),
    ] {
        let mut window = Window::new(3, 5, NONCE).unwrap();
        assert_eq!(
            window.accept(code, flags, first, pid, tid, &pre),
            Err(reason)
        );
        assert_eq!(window.state, State::AwaitPre);
        assert!(window.api.is_none() && window.result.is_none());
    }
    for (index, value, reason) in [
        (0, 99, Rejection::Version),
        (1, 99, Rejection::PhaseOrder),
        (2, 99, Rejection::Nonce),
        (3, 99, Rejection::Nonce),
        (4, 0, Rejection::ApiNonzero),
        (5, 1, Rejection::PreResultZero),
        (5, 2, Rejection::ResultRange),
        (6, 5, Rejection::PreResultZero),
        (6, u64::MAX, Rejection::ResultRange),
    ] {
        let mut window = Window::new(3, 5, NONCE).unwrap();
        let mut packet = pre;
        packet[index] = value;
        assert_eq!(accept(&mut window, &packet), Err(reason));
        assert_eq!(window.state, State::AwaitPre);
        assert!(window.api.is_none() && window.result.is_none());
    }
    let mut window = Window::new(3, 5, NONCE).unwrap();
    assert_eq!(
        accept(&mut window, &pre[..6]),
        Err(Rejection::ParameterCount)
    );
    accept(&mut window, &pre).unwrap();
    assert_eq!(accept(&mut window, &pre), Err(Rejection::PhaseOrder));
    for (index, value, reason) in [
        (4, API + 1, Rejection::PostApiMatch),
        (5, 1, Rejection::PostResultConsistency),
    ] {
        let mut post = Packet::post(NONCE, API, false, 5).unwrap();
        post[index] = value;
        assert_eq!(accept(&mut window, &post), Err(reason));
        assert_eq!(window.state, State::AwaitPost);
        assert_eq!(window.api, Some(API));
        assert!(window.result.is_none());
    }
    assert_eq!(
        serde_json::to_value(Rejection::PreResultZero).unwrap(),
        "pre-result-zero"
    );
    assert_eq!(Rejection::Flags.to_string(), "invalid replay call marker");
}

#[test]
fn documented_software_origin_accepts_only_zero_or_the_exact_system_flag() {
    let nonce = "373344eb7ceaa562ce37add8c2ae2495";
    let api = 140723528495088;
    let pre = [1, 1, 7108345409118155575, 10746906762694965198, api, 0, 0];
    assert_eq!(Packet::pre(nonce, api).unwrap(), pre);
    for flags in [0, EXCEPTION_SOFTWARE_ORIGINATE] {
        let mut window = Window::new(4024, 9764, nonce).unwrap();
        assert_eq!(
            window.accept(CODE, flags, true, 4024, 9764, &pre),
            Ok(Phase::Pre)
        );
        let post = Packet::post(nonce, api, false, 5).unwrap();
        assert_eq!(
            window.accept(CODE, flags, true, 4024, 9764, &post),
            Ok(Phase::Post)
        );
        assert_eq!(
            window.result,
            Some(CallResult {
                opened: false,
                raw_error: 5
            })
        );
    }
    for bit in 0..u32::BITS {
        let flag = 1u32 << bit;
        if flag == EXCEPTION_SOFTWARE_ORIGINATE {
            continue;
        }
        for flags in [flag, flag | EXCEPTION_SOFTWARE_ORIGINATE, u32::MAX] {
            let mut window = Window::new(4024, 9764, nonce).unwrap();
            assert_eq!(
                window.accept(CODE, flags, true, 4024, 9764, &pre),
                Err(Rejection::Flags)
            );
            assert_eq!(window.state, State::AwaitPre);
            assert!(window.api.is_none() && window.result.is_none());
            window.accept(CODE, 0, true, 4024, 9764, &pre).unwrap();
            assert_eq!(
                window.accept(
                    CODE,
                    flags,
                    true,
                    4024,
                    9764,
                    &Packet::post(nonce, api, false, 5).unwrap()
                ),
                Err(Rejection::Flags)
            );
            assert_eq!(window.state, State::AwaitPost);
            assert!(window.result.is_none());
        }
    }
}

#[test]
fn software_origin_never_substitutes_for_other_marker_guards() {
    let pre = Packet::pre(NONCE, API).unwrap();
    for (code, first, pid, tid, expected) in [
        (CODE + 1, true, 3, 5, Rejection::Code),
        (CODE, false, 3, 5, Rejection::FirstChance),
        (CODE, true, 4, 5, Rejection::OwnerPid),
        (CODE, true, 3, 6, Rejection::OwnerTid),
    ] {
        let mut window = Window::new(3, 5, NONCE).unwrap();
        assert_eq!(
            window.accept(code, EXCEPTION_SOFTWARE_ORIGINATE, first, pid, tid, &pre),
            Err(expected)
        );
        assert_eq!(window.state, State::AwaitPre);
    }
    for (index, value, expected) in [
        (0, 2, Rejection::Version),
        (1, packet::PHASE_POST, Rejection::PhaseOrder),
        (2, 99, Rejection::Nonce),
        (4, 0, Rejection::ApiNonzero),
        (5, 1, Rejection::PreResultZero),
    ] {
        let mut window = Window::new(3, 5, NONCE).unwrap();
        let mut bad = pre;
        bad[index] = value;
        assert_eq!(
            window.accept(CODE, EXCEPTION_SOFTWARE_ORIGINATE, true, 3, 5, &bad),
            Err(expected)
        );
        assert_eq!(window.state, State::AwaitPre);
    }
    let mut window = Window::new(3, 5, NONCE).unwrap();
    assert_eq!(
        window.accept(CODE, EXCEPTION_SOFTWARE_ORIGINATE, true, 3, 5, &pre[..6]),
        Err(Rejection::ParameterCount)
    );
    window
        .accept(CODE, EXCEPTION_SOFTWARE_ORIGINATE, true, 3, 5, &pre)
        .unwrap();
    assert_eq!(
        window.accept(CODE, EXCEPTION_SOFTWARE_ORIGINATE, true, 3, 5, &pre),
        Err(Rejection::PhaseOrder)
    );
    let mut post = Packet::post(NONCE, API + 1, false, 5).unwrap();
    assert_eq!(
        window.accept(CODE, EXCEPTION_SOFTWARE_ORIGINATE, true, 3, 5, &post),
        Err(Rejection::PostApiMatch)
    );
    post[4] = API;
    post[5] = 1;
    assert_eq!(
        window.accept(CODE, EXCEPTION_SOFTWARE_ORIGINATE, true, 3, 5, &post),
        Err(Rejection::PostResultConsistency)
    );
    assert_eq!(window.state, State::AwaitPost);
    assert!(window.result.is_none());
}
