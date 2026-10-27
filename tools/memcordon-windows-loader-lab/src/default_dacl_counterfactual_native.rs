//! Private diagnostic duplicate only. Never alters the retained source token.
use super::*;
use memcordon_windows_loader_lab::default_dacl_counterfactual as contract;

struct RestrictedSid(PSID);
impl Drop for RestrictedSid {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(super) struct Duplicate {
    pub token: Handle,
    pub source: Value,
    pub changed: Value,
}

impl Duplicate {
    pub fn create(source: HANDLE, work: Instant, refusal: &mut Value) -> Result<Self, String> {
        live(work)?;
        let before = startup_access_probes::token_snapshot(source)?;
        let restricting = json!({"captured":true,"facts":before["security"]["restricting_sids"]});
        let expected = contract::expected_acl(&before["default_dacl"], &restricting)?;
        let mut raw = ptr::null_mut();
        if unsafe {
            DuplicateTokenEx(
                source,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &mut raw,
            )
        } == 0
        {
            return Err(error(
                "DuplicateTokenEx private default-DACL diagnostic primary",
            ));
        }
        let token = Handle::new(raw)?;
        let mut flags = 0;
        if unsafe { GetHandleInformation(token.0, &mut flags) } == 0
            || flags & HANDLE_FLAG_INHERIT != 0
        {
            return Err(
                "counterfactual duplicate token handle is not retained noninheritable".into(),
            );
        }
        let unmodified = startup_access_probes::token_snapshot(token.0)?;
        if !contract::unchanged_security(&unmodified, &before)
            || memcordon_windows_loader_lab::startup_probe_contract::default_dacl_equality(
                &before["default_dacl"],
                &unmodified["default_dacl"],
            ) != Some(true)
        {
            *refusal = contract::duplicate_refusal(&before, &unmodified);
            return Err("private duplicate differs before diagnostic intervention".into());
        }
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide("S-1-5-12").as_ptr(), &mut sid) } == 0 {
            return Err(error("counterfactual RestrictedCode SID"));
        }
        let sid = RestrictedSid(sid);
        if unsafe { IsValidSid(sid.0) } == 0 {
            return Err("counterfactual RC SID is invalid".into());
        }
        let sid_bytes =
            usize::try_from(unsafe { GetLengthSid(sid.0) }).map_err(|error| error.to_string())?;
        let original = hex::decode(
            before["default_dacl"]["facts"]["raw_hex"]
                .as_str()
                .ok_or("original raw ACL absent")?,
        )
        .map_err(|error| error.to_string())?;
        let capacity = original
            .len()
            .checked_add(size_of::<ACE_HEADER>())
            .and_then(|size| size.checked_add(size_of::<u32>()))
            .and_then(|size| size.checked_add(sid_bytes))
            .filter(|size| *size == expected.len())
            .ok_or("native SID length differs from exact appended ACL capacity")?;
        // Aligned private ACL storage is never installed on a process or global
        // object. Initialize/copy preserve the original ACE bytes and order.
        let mut storage = vec![0_u32; capacity.div_ceil(size_of::<u32>())];
        let acl = storage.as_mut_ptr().cast::<ACL>();
        let capacity = u32::try_from(capacity).map_err(|error| error.to_string())?;
        let revision = u32::from(expected[0]);
        if unsafe { InitializeAcl(acl, capacity, revision) } == 0 {
            return Err(error("InitializeAcl private diagnostic ACL"));
        }
        let aces = before["default_dacl"]["facts"]["aces"]
            .as_array()
            .ok_or("original ACE inventory absent")?;
        for ace in aces {
            live(work)?;
            let bytes = hex::decode(ace["raw_hex"].as_str().ok_or("original raw ACE absent")?)
                .map_err(|error| error.to_string())?;
            if unsafe {
                AddAce(
                    acl,
                    revision,
                    u32::MAX,
                    bytes.as_ptr().cast(),
                    u32::try_from(bytes.len()).map_err(|error| error.to_string())?,
                )
            } == 0
            {
                return Err(error("AddAce exact original diagnostic ACL entry"));
            }
        }
        if unsafe { AddAccessAllowedAceEx(acl, revision, 0, 0x1000_0000, sid.0) } == 0 {
            return Err(error("AddAccessAllowedAceEx private diagnostic RC entry"));
        }
        if unsafe { IsValidAcl(acl) } == 0 {
            return Err("counterfactual constructed ACL is invalid".into());
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), expected.len()) };
        if bytes != expected {
            return Err("native ACL construction differs from exact sole-ACE contract".into());
        }
        live(work)?;
        let selected = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
        if unsafe {
            SetTokenInformation(
                token.0,
                TokenDefaultDacl,
                (&selected as *const TOKEN_DEFAULT_DACL).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        } == 0
        {
            return Err(error("SetTokenInformation private duplicate default DACL"));
        }
        let changed = startup_access_probes::token_snapshot(token.0)?;
        let after = startup_access_probes::token_snapshot(source)?;
        contract::verify_delta(
            &before["default_dacl"],
            &after["default_dacl"],
            &restricting,
            &changed["default_dacl"],
        )?;
        if before != after || !contract::unchanged_security(&before, &changed) {
            return Err("counterfactual changes original token or non-DACL security facts".into());
        }
        live(work)?;
        Ok(Self {
            token,
            source: before,
            changed,
        })
    }

    pub fn attest(&self, source: HANDLE, actual: HANDLE, work: Instant) -> Result<Value, String> {
        live(work)?;
        let original = startup_access_probes::token_snapshot(source)?;
        let duplicate = startup_access_probes::token_snapshot(self.token.0)?;
        let actual = startup_access_probes::token_snapshot(actual)?;
        if original != self.source
            || duplicate != self.changed
            || !contract::unchanged_security(&actual, &self.changed)
            || memcordon_windows_loader_lab::startup_probe_contract::default_dacl_equality(
                &self.changed["default_dacl"],
                &actual["default_dacl"],
            ) != Some(true)
        {
            return Err(
                "counterfactual source/duplicate/actual suspended token readback differs".into(),
            );
        }
        live(work)?;
        Ok(
            json!({"source":original,"duplicate":duplicate,"actual_suspended":actual,
            "default_dacl_counterfactual":true,"reference_plan_default_dacl_equivalence":false,
            "only_duplicate_default_acl_changed":true,"diagnostic_only":true}),
        )
    }

    pub fn verify_retired(&self, source: HANDLE, cleanup: Instant) -> Result<(), String> {
        live(cleanup)?;
        if startup_access_probes::token_snapshot(source)? != self.source
            || startup_access_probes::token_snapshot(self.token.0)? != self.changed
        {
            return Err("counterfactual token changed during owned execution/retirement".into());
        }
        live(cleanup)?;
        Ok(())
    }
}
