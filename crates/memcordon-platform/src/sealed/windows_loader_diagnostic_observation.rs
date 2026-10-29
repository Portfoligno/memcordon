//! Separate support-only observation; never a certification acceptance row.
use memcordon_core::{
    WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION, WindowsLaunchRequestV2,
    WindowsLoaderDiagnosticSelectionV1, WindowsProcessIdentityV1, WindowsProviderRequestV4,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, marker::PhantomData, rc::Rc};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLoaderDiagnosticObservation {
    pub selection: WindowsLoaderDiagnosticSelectionV1,
    pub launch: Option<WindowsLaunchRequestV2>,
    pub caller: Option<WindowsProcessIdentityV1>,
    pub attempt_id: Option<String>,
    pub request_sha256: Option<String>,
    pub authenticated_provider_frames: Vec<Vec<u8>>,
    pub capture_failure: Option<String>,
}

thread_local! { static ACTIVE: RefCell<Option<WindowsLoaderDiagnosticObservation>> = const { RefCell::new(None) }; }

pub struct WindowsLoaderDiagnosticScope {
    _thread: PhantomData<Rc<()>>,
}

impl WindowsLoaderDiagnosticScope {
    pub fn begin(selection: WindowsLoaderDiagnosticSelectionV1) -> Result<Self, String> {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if active.is_some() || super::certification_observation::active() {
                return Err("loader diagnostic requires its own separate observation scope".into());
            }
            *active = Some(WindowsLoaderDiagnosticObservation {
                selection,
                launch: None,
                caller: None,
                attempt_id: None,
                request_sha256: None,
                authenticated_provider_frames: Vec::new(),
                capture_failure: None,
            });
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
    pub fn finish(self) -> Result<WindowsLoaderDiagnosticObservation, String> {
        ACTIVE.with(|active| {
            active
                .borrow_mut()
                .take()
                .ok_or_else(|| "loader diagnostic observation owner missing".into())
        })
    }
}

impl Drop for WindowsLoaderDiagnosticScope {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.borrow_mut().take();
        });
    }
}

pub(super) fn decorate(launch: &mut WindowsLaunchRequestV2) -> Result<(), String> {
    ACTIVE.with(|active| {
        if let Some(observation) = active.borrow().as_ref() {
            if observation.launch.is_some() || super::certification_observation::active() {
                return Err("loader diagnostic permits exactly one separate support launch".into());
            }
            launch.loader_diagnostic = Some(Box::new(observation.selection.clone()));
        }
        Ok(())
    })
}

pub(super) fn route(launch: WindowsLaunchRequestV2) -> Result<WindowsProviderRequestV4, String> {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let Some(observation) = active.as_mut() else {
            return super::certification_observation::route(launch);
        };
        if observation.launch.is_some()
            || launch.loader_diagnostic.as_deref() != Some(&observation.selection)
        {
            return Err("loader diagnostic canonical launch selection differs".into());
        }
        let caller = super::certification_observation::caller_identity()?;
        let digest = hex(&Sha256::digest(
            serde_json::to_vec(&launch).map_err(|error| error.to_string())?,
        ));
        let mut identity = Sha256::new();
        identity.update(launch.nonce.as_bytes());
        identity.update(caller.process_id.to_le_bytes());
        identity.update(caller.creation_time_100ns.to_le_bytes());
        identity.update(digest.as_bytes());
        let attempt = hex(&identity.finalize());
        observation.launch = Some(launch.clone());
        observation.caller = Some(caller.clone());
        observation.attempt_id = Some(attempt.clone());
        observation.request_sha256 = Some(digest.clone());
        Ok(WindowsProviderRequestV4::LoaderDiagnosticLaunch {
            schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
            attempt_id: attempt,
            request_sha256: digest,
            caller_process_identity: caller,
            launch,
        })
    })
}

pub(super) fn frame(bytes: &[u8]) {
    ACTIVE.with(|active| {
        if let Some(observation) = active.borrow_mut().as_mut() {
            // Pre-launch probe/plan exchanges are not diagnostic launch frames.
            // route() binds the exact original request before its first read.
            if observation.launch.is_none() {
                return;
            }
            let total = observation
                .authenticated_provider_frames
                .iter()
                .map(Vec::len)
                .sum::<usize>();
            if observation.authenticated_provider_frames.len() >= 16
                || total.saturating_add(bytes.len()) > 1024 * 1024
            {
                observation.capture_failure =
                    Some("loader diagnostic authenticated frame bound exceeded".into());
            } else {
                observation
                    .authenticated_provider_frames
                    .push(bytes.to_vec());
            }
        }
    });
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
