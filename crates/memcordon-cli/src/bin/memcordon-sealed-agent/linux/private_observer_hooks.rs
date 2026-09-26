//! Fixed observation points for the independently pinned qualification
//! probe. These functions have no policy input and never choose behavior.
//! A call is not evidence by itself: only a loss-free attached kernel capture
//! can observe it, and allocation still requires actual task/retirement joins.

#[unsafe(no_mangle)]
#[inline(never)]
pub(crate) extern "C" fn mc_private_request_enter_v1() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
pub(crate) extern "C" fn mc_private_request_exit_v1() {
    std::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
pub(crate) extern "C" fn mc_private_allocate_v1() {
    std::hint::black_box(());
}
