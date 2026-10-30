//! Own the foreign-call buffer with the public x64 CONTEXT alignment contract.
//! The caller retains the SDK structure as the sole field; no layout is rebuilt.
#[repr(C, align(16))]
pub struct ContextStorage<T>(pub T);
