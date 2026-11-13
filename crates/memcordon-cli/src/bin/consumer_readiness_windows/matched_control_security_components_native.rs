//! Read-only accessors after independent same-buffer structural validation.
use super::{OwnedDescriptor, components::*, descriptor, live, relative_descriptor_structure};
use sha2::{Digest, Sha256};
use std::{ffi::c_void, io, time::Instant};
use windows_sys::Win32::Security::{
    ACL, ACL_SIZE_INFORMATION, AclSizeInformation, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorGroup,
    GetSecurityDescriptorLength, GetSecurityDescriptorOwner, GetSecurityDescriptorSacl, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid,
};

type Failure = (Stage, Option<i32>);
fn failed(stage: Stage) -> Failure {
    (stage, io::Error::last_os_error().raw_os_error())
}
fn guard(cutoff: Instant) -> Result<(), Failure> {
    live(cutoff).map_err(|_| (Stage::Cutoff, None))
}

struct Access<'a> {
    descriptor: &'a OwnedDescriptor,
    bytes: Vec<u8>,
    cutoff: Instant,
}
impl Access<'_> {
    fn pointer(&self) -> *mut c_void {
        self.descriptor.as_ptr()
    }
    fn offset(&self, pointer: *mut c_void) -> Result<usize, Failure> {
        component_offset(self.pointer() as usize, self.bytes.len(), pointer as usize)
            .map_err(|stage| (stage, None))
    }
    fn span(&self, offset: usize, length: u32) -> Result<&[u8], Failure> {
        component_bytes(&self.bytes, offset, length as usize).map_err(|stage| (stage, None))
    }
    fn sid(&self, owner: bool) -> Result<Sid, Failure> {
        guard(self.cutoff)?;
        let mut pointer = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: both independent validators proved this immutable live
        // relative descriptor before any pointer-returning accessor.
        let result = unsafe {
            if owner {
                GetSecurityDescriptorOwner(self.pointer(), &mut pointer, &mut defaulted)
            } else {
                GetSecurityDescriptorGroup(self.pointer(), &mut pointer, &mut defaulted)
            }
        };
        if result == 0 {
            return Err(failed(if owner { Stage::Owner } else { Stage::Group }));
        }
        guard(self.cutoff)?;
        if pointer.is_null() {
            return Ok(Sid::Absent {});
        } // defaulted is undefined here.
        let offset = self.offset(pointer)?;
        // SAFETY: the length-aware descriptor validator proved the pointed SID
        // readable; membership was checked before this native SID validation.
        if unsafe { IsValidSid(pointer) } == 0 {
            return Err((Stage::SidValidity, None));
        }
        guard(self.cutoff)?;
        // SAFETY: GetLengthSid is called only after IsValidSid succeeds.
        let length = unsafe { GetLengthSid(pointer) };
        guard(self.cutoff)?;
        if length == 0 {
            return Err((Stage::SidLength, None));
        }
        let bytes = self.span(offset, length)?;
        Ok(Sid::Observed {
            defaulted: defaulted != 0,
            bytes: length,
            sha256: Sha256::digest(bytes).into(),
        })
    }
    fn acl(&self, label_subset: bool) -> Result<Acl, Failure> {
        guard(self.cutoff)?;
        let mut present = 0;
        let mut pointer: *mut ACL = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: the immutable descriptor was independently validated. The
        // returned SACL is only the LABEL subset requested by original mask23.
        let result = unsafe {
            if label_subset {
                GetSecurityDescriptorSacl(
                    self.pointer(),
                    &mut present,
                    &mut pointer,
                    &mut defaulted,
                )
            } else {
                GetSecurityDescriptorDacl(
                    self.pointer(),
                    &mut present,
                    &mut pointer,
                    &mut defaulted,
                )
            }
        };
        if result == 0 {
            return Err(failed(if label_subset {
                Stage::LabelSaclSubset
            } else {
                Stage::Dacl
            }));
        }
        guard(self.cutoff)?;
        if present == 0 {
            return Ok(Acl::Absent {});
        } // other outputs are undefined.
        if pointer.is_null() {
            return Ok(Acl::Null {
                defaulted: defaulted != 0,
            });
        }
        let offset = self.offset(pointer.cast())?;
        // SAFETY: descriptor structure proved the ACL readable; exact-buffer
        // membership was checked before invoking the native ACL validator.
        if unsafe { IsValidAcl(pointer) } == 0 {
            return Err((Stage::AclValidity, None));
        }
        guard(self.cutoff)?;
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: pointer is a validated nonnull ACL; output has its SDK size.
        if unsafe {
            GetAclInformation(
                pointer,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(failed(Stage::AclInformation));
        }
        guard(self.cutoff)?;
        if information.AclBytesInUse < std::mem::size_of::<ACL>() as u32 {
            return Err((Stage::ComponentBounds, None));
        }
        let total = information
            .AclBytesInUse
            .checked_add(information.AclBytesFree)
            .ok_or((Stage::ComponentBounds, None))?;
        let used = self.span(offset, information.AclBytesInUse)?;
        let all = self.span(offset, total)?;
        Ok(Acl::Observed {
            defaulted: defaulted != 0,
            ace_count: information.AceCount,
            bytes_in_use: information.AclBytesInUse,
            bytes_free: information.AclBytesFree,
            used_sha256: Sha256::digest(used).into(),
            total_sha256: Sha256::digest(all).into(),
        })
    }
}

pub(super) fn capture(owned: &OwnedDescriptor, cutoff: Instant) -> Components {
    let result = (|| -> Result<Components, Failure> {
        let extent = u32::try_from(owned.extent).map_err(|_| (Stage::BufferBounds, None))?;
        let pointer = owned.as_ptr();
        // Run this prerequisite for BOTH positive and zero returned-length
        // captures. It is structural only and never changes input acceptance.
        let validated = descriptor::validate_zero(
            &owned.words,
            extent,
            || live(cutoff).is_ok(),
            |bound| relative_descriptor_structure(pointer, bound, cutoff),
            // SAFETY: the length-aware relative validator ran first.
            || unsafe { IsValidSecurityDescriptor(pointer) },
            // SAFETY: both native validity prerequisites succeeded.
            || unsafe { GetSecurityDescriptorLength(pointer) },
        )
        .map_err(|facts| {
            use descriptor::State;
            (
                match facts.state {
                    State::BufferBoundInvalid => Stage::BufferBounds,
                    State::HeaderInvalid => Stage::Header,
                    State::ExportUnavailable => Stage::ValidatorUnavailable,
                    State::Cutoff => Stage::Cutoff,
                    State::RelativeInvalid => Stage::RelativeValidation,
                    State::NativeInvalid => Stage::NativeValidation,
                    State::LengthOutsideBuffer | State::Observed => Stage::NativeLength,
                },
                None,
            )
        })?;
        let native_bytes = validated.byte_len() as u32;
        let access = Access {
            descriptor: owned,
            bytes: validated.bytes(),
            cutoff,
        };
        guard(cutoff)?;
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: both independent validators succeeded on this same owner.
        if unsafe { GetSecurityDescriptorControl(pointer, &mut control, &mut revision) } == 0 {
            return Err(failed(Stage::Control));
        }
        guard(cutoff)?;
        let owner = access.sid(true)?;
        let group = access.sid(false)?;
        let dacl = access.acl(false)?;
        let label_sacl_subset = access.acl(true)?;
        guard(cutoff)?;
        Ok(Components::Observed(Box::new(ObservedComponents {
            revision,
            control,
            native_bytes,
            owner,
            group,
            dacl,
            label_sacl_subset,
        })))
    })();
    match result {
        Ok(observed) => observed,
        Err((stage, error)) => Components::unavailable(stage, error),
    }
}
