#![cfg(target_os = "linux")]

#[test]
fn frontend_loss_armed_response_is_bound_to_its_own_release_selector() {
    let challenge = [0x5a; 32];
    let frontend = crate::linux::private_release_frontend_loss::armed_response(&challenge);
    let guardian = crate::linux::private_release_guardian_loss::armed_response(&challenge);
    assert_ne!(frontend, guardian);
    assert_ne!(frontend, [0; 32]);
}
