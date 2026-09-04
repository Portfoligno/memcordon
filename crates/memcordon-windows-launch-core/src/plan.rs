use crate::{
    DesktopBindingV1, ExactHandleListV1, PreparedEnvironmentIdentityV1, TargetTokenIdentityV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const DEBUG_PROCESS: u32 = 0x0000_0001;
const DEBUG_ONLY_THIS_PROCESS: u32 = 0x0000_0002;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionLoaderPlanInputV1 {
    /// Exact Windows path code units, excluding the native trailing NUL.
    pub executable_path_utf16: Vec<u16>,
    pub executable_sha256: String,
    pub command_line_sha256: String,
    pub environment: PreparedEnvironmentIdentityV1,
    pub current_directory_sha256: String,
    pub desktop: DesktopBindingV1,
    pub process_security_descriptor_sddl: String,
    pub thread_security_descriptor_sddl: String,
    pub job_security_descriptor_sddl: String,
    pub loader_ready_pipe_security_descriptor_sddl: String,
    pub target_token: TargetTokenIdentityV1,
    pub inherited_handles: ExactHandleListV1,
    pub job_at_creation: bool,
}

/// Constructs the package loader plan without admitting certification marker
/// state into the native launch contract.
pub fn build_package_loader_plan(
    input: ProductionLoaderPlanInputV1,
) -> Result<ProductionLoaderPlanV1, ProductionPlanError> {
    ProductionLoaderPlanV1::new(input)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProductionLoaderPlanV1 {
    schema_version: u32,
    executable_path_utf16: Vec<u16>,
    executable_sha256: String,
    command_line_sha256: String,
    environment: PreparedEnvironmentIdentityV1,
    current_directory_sha256: String,
    desktop: DesktopBindingV1,
    process_security_descriptor_sha256: String,
    thread_security_descriptor_sha256: String,
    process_security_descriptor_sddl: String,
    thread_security_descriptor_sddl: String,
    job_security_descriptor_sha256: String,
    job_security_descriptor_sddl: String,
    loader_ready_pipe_security_descriptor_sha256: String,
    loader_ready_pipe_security_descriptor_sddl: String,
    target_token: TargetTokenIdentityV1,
    inherited_handles: ExactHandleListV1,
    job_at_creation: bool,
    creation_flags: u32,
    launch_plan_sha256: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProductionPlanError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("production loader plans require Job assignment at process creation")]
    MissingCreationJob,
    #[error("production loader control requires an exact empty inherited-handle list")]
    NonemptyHandleList,
}

impl ProductionLoaderPlanV1 {
    pub const CREATION_FLAGS: u32 =
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;

    pub fn new(input: ProductionLoaderPlanInputV1) -> Result<Self, ProductionPlanError> {
        if input.executable_path_utf16.is_empty() || input.executable_path_utf16.contains(&0) {
            return Err(ProductionPlanError::Empty {
                field: "executable_path_utf16",
            });
        }
        require_nonempty("desktop.exact_name", &input.desktop.exact_name)?;
        if input.desktop.exact_name.contains('\0') {
            return Err(ProductionPlanError::Empty {
                field: "desktop.exact_name",
            });
        }
        if input.environment.encoding != "utf-16le-double-nul" {
            return Err(ProductionPlanError::Empty {
                field: "environment.encoding",
            });
        }
        require_digest("executable_sha256", &input.executable_sha256)?;
        require_digest("command_line_sha256", &input.command_line_sha256)?;
        require_digest("environment.sha256", &input.environment.sha256)?;
        require_digest("current_directory_sha256", &input.current_directory_sha256)?;
        require_digest(
            "desktop.security_descriptor_sha256",
            &input.desktop.security_descriptor_sha256,
        )?;
        for (field, sddl) in [
            (
                "desktop.window_station_security_descriptor_sddl",
                input
                    .desktop
                    .window_station_security_descriptor_sddl
                    .as_str(),
            ),
            (
                "desktop.desktop_security_descriptor_sddl",
                input.desktop.desktop_security_descriptor_sddl.as_str(),
            ),
        ] {
            require_nonempty(field, sddl)?;
            if sddl.contains('\0') {
                return Err(ProductionPlanError::Empty { field });
            }
        }
        require_nonempty(
            "process_security_descriptor_sddl",
            &input.process_security_descriptor_sddl,
        )?;
        require_nonempty(
            "thread_security_descriptor_sddl",
            &input.thread_security_descriptor_sddl,
        )?;
        require_nonempty(
            "job_security_descriptor_sddl",
            &input.job_security_descriptor_sddl,
        )?;
        require_nonempty(
            "loader_ready_pipe_security_descriptor_sddl",
            &input.loader_ready_pipe_security_descriptor_sddl,
        )?;
        if input.process_security_descriptor_sddl.contains('\0')
            || input.thread_security_descriptor_sddl.contains('\0')
            || input.job_security_descriptor_sddl.contains('\0')
            || input
                .loader_ready_pipe_security_descriptor_sddl
                .contains('\0')
        {
            return Err(ProductionPlanError::Empty {
                field: "security_descriptor_sddl",
            });
        }
        require_digest(
            "target_token.envelope_sha256",
            &input.target_token.envelope_sha256,
        )?;
        if !input.job_at_creation {
            return Err(ProductionPlanError::MissingCreationJob);
        }
        if !input.inherited_handles.roles().is_empty() {
            return Err(ProductionPlanError::NonemptyHandleList);
        }

        let mut plan = Self {
            schema_version: 1,
            executable_path_utf16: input.executable_path_utf16,
            executable_sha256: input.executable_sha256,
            command_line_sha256: input.command_line_sha256,
            environment: input.environment,
            current_directory_sha256: input.current_directory_sha256,
            desktop: input.desktop,
            process_security_descriptor_sha256: hex::encode(Sha256::digest(
                input.process_security_descriptor_sddl.as_bytes(),
            )),
            thread_security_descriptor_sha256: hex::encode(Sha256::digest(
                input.thread_security_descriptor_sddl.as_bytes(),
            )),
            process_security_descriptor_sddl: input.process_security_descriptor_sddl,
            thread_security_descriptor_sddl: input.thread_security_descriptor_sddl,
            job_security_descriptor_sha256: hex::encode(Sha256::digest(
                input.job_security_descriptor_sddl.as_bytes(),
            )),
            job_security_descriptor_sddl: input.job_security_descriptor_sddl,
            loader_ready_pipe_security_descriptor_sha256: hex::encode(Sha256::digest(
                input.loader_ready_pipe_security_descriptor_sddl.as_bytes(),
            )),
            loader_ready_pipe_security_descriptor_sddl: input
                .loader_ready_pipe_security_descriptor_sddl,
            target_token: input.target_token,
            inherited_handles: input.inherited_handles,
            job_at_creation: true,
            creation_flags: Self::CREATION_FLAGS,
            launch_plan_sha256: String::new(),
        };
        plan.launch_plan_sha256 =
            hex::encode(Sha256::digest(plan.canonical_bytes_without_digest()));
        Ok(plan)
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.canonical_bytes_without_digest();
        append_field(&mut bytes, self.launch_plan_sha256.as_bytes());
        bytes
    }

    #[must_use]
    pub const fn debugger_is_unrepresentable(&self) -> bool {
        self.creation_flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS) == 0
    }

    #[must_use]
    pub const fn creation_flags(&self) -> u32 {
        self.creation_flags
    }

    #[must_use]
    pub fn launch_plan_sha256(&self) -> &str {
        &self.launch_plan_sha256
    }

    /// Digest of the shipped launch shape with per-install and per-attempt
    /// identities removed. This is for cross-run channel comparison only;
    /// native attestation always uses `launch_plan_sha256`.
    #[must_use]
    pub fn template_sha256(&self) -> String {
        let mut template = self.clone();
        template.executable_path_utf16 = "<installed-bootstrap>".encode_utf16().collect();
        template.executable_sha256 = zero_digest();
        template.command_line_sha256 = zero_digest();
        template.current_directory_sha256 = zero_digest();
        template.desktop.exact_name = String::from("<ephemeral-private-desktop>");
        template.target_token = TargetTokenIdentityV1 {
            envelope_sha256: zero_digest(),
            authentication_id: 0,
            session_id: 0,
        };
        template.launch_plan_sha256.clear();
        hex::encode(Sha256::digest(template.canonical_bytes_without_digest()))
    }

    #[must_use]
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    #[must_use]
    pub fn command_line_sha256(&self) -> &str {
        &self.command_line_sha256
    }

    #[must_use]
    pub fn environment(&self) -> &PreparedEnvironmentIdentityV1 {
        &self.environment
    }

    #[must_use]
    pub fn current_directory_sha256(&self) -> &str {
        &self.current_directory_sha256
    }

    #[must_use]
    pub fn process_security_descriptor_sha256(&self) -> &str {
        &self.process_security_descriptor_sha256
    }

    #[must_use]
    pub fn thread_security_descriptor_sha256(&self) -> &str {
        &self.thread_security_descriptor_sha256
    }

    #[must_use]
    pub fn process_security_descriptor_sddl(&self) -> &str {
        &self.process_security_descriptor_sddl
    }

    #[must_use]
    pub fn thread_security_descriptor_sddl(&self) -> &str {
        &self.thread_security_descriptor_sddl
    }

    #[must_use]
    pub fn job_security_descriptor_sha256(&self) -> &str {
        &self.job_security_descriptor_sha256
    }

    #[must_use]
    pub fn job_security_descriptor_sddl(&self) -> &str {
        &self.job_security_descriptor_sddl
    }

    #[must_use]
    pub fn loader_ready_pipe_security_descriptor_sha256(&self) -> &str {
        &self.loader_ready_pipe_security_descriptor_sha256
    }

    #[must_use]
    pub fn loader_ready_pipe_security_descriptor_sddl(&self) -> &str {
        &self.loader_ready_pipe_security_descriptor_sddl
    }

    #[must_use]
    pub fn executable_path_utf16(&self) -> &[u16] {
        &self.executable_path_utf16
    }

    #[must_use]
    pub fn desktop(&self) -> &DesktopBindingV1 {
        &self.desktop
    }

    #[must_use]
    pub fn target_token(&self) -> &TargetTokenIdentityV1 {
        &self.target_token
    }

    #[must_use]
    pub fn inherited_handles(&self) -> &ExactHandleListV1 {
        &self.inherited_handles
    }

    #[must_use]
    pub const fn job_at_creation(&self) -> bool {
        self.job_at_creation
    }

    fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_field(&mut bytes, &self.schema_version.to_le_bytes());
        for unit in &self.executable_path_utf16 {
            append_field(&mut bytes, &unit.to_le_bytes());
        }
        append_field(&mut bytes, self.executable_sha256.as_bytes());
        append_field(&mut bytes, self.command_line_sha256.as_bytes());
        append_field(&mut bytes, self.environment.encoding.as_bytes());
        append_field(&mut bytes, &self.environment.byte_len.to_le_bytes());
        append_field(&mut bytes, self.environment.sha256.as_bytes());
        append_field(&mut bytes, self.current_directory_sha256.as_bytes());
        append_field(&mut bytes, self.desktop.exact_name.as_bytes());
        append_field(
            &mut bytes,
            self.desktop.security_descriptor_sha256.as_bytes(),
        );
        append_field(
            &mut bytes,
            self.desktop
                .window_station_security_descriptor_sddl
                .as_bytes(),
        );
        append_field(
            &mut bytes,
            self.desktop.desktop_security_descriptor_sddl.as_bytes(),
        );
        append_field(
            &mut bytes,
            self.process_security_descriptor_sha256.as_bytes(),
        );
        append_field(
            &mut bytes,
            self.thread_security_descriptor_sha256.as_bytes(),
        );
        append_field(&mut bytes, self.process_security_descriptor_sddl.as_bytes());
        append_field(&mut bytes, self.thread_security_descriptor_sddl.as_bytes());
        append_field(&mut bytes, self.job_security_descriptor_sha256.as_bytes());
        append_field(&mut bytes, self.job_security_descriptor_sddl.as_bytes());
        append_field(
            &mut bytes,
            self.loader_ready_pipe_security_descriptor_sha256.as_bytes(),
        );
        append_field(
            &mut bytes,
            self.loader_ready_pipe_security_descriptor_sddl.as_bytes(),
        );
        append_field(&mut bytes, self.target_token.envelope_sha256.as_bytes());
        append_field(
            &mut bytes,
            &self.target_token.authentication_id.to_le_bytes(),
        );
        append_field(&mut bytes, &self.target_token.session_id.to_le_bytes());
        append_field(
            &mut bytes,
            &(self.inherited_handles.roles().len() as u64).to_le_bytes(),
        );
        for role in self.inherited_handles.roles() {
            let value = serde_json::to_vec(role).expect("handle roles always serialize");
            append_field(&mut bytes, &value);
        }
        append_field(&mut bytes, &[u8::from(self.job_at_creation)]);
        append_field(&mut bytes, &self.creation_flags.to_le_bytes());
        bytes
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionLoaderPlanWireV1 {
    schema_version: u32,
    executable_path_utf16: Vec<u16>,
    executable_sha256: String,
    command_line_sha256: String,
    environment: PreparedEnvironmentIdentityV1,
    current_directory_sha256: String,
    desktop: DesktopBindingV1,
    process_security_descriptor_sha256: String,
    thread_security_descriptor_sha256: String,
    process_security_descriptor_sddl: String,
    thread_security_descriptor_sddl: String,
    job_security_descriptor_sha256: String,
    job_security_descriptor_sddl: String,
    loader_ready_pipe_security_descriptor_sha256: String,
    loader_ready_pipe_security_descriptor_sddl: String,
    target_token: TargetTokenIdentityV1,
    inherited_handles: ExactHandleListV1,
    job_at_creation: bool,
    creation_flags: u32,
    launch_plan_sha256: String,
}

impl<'de> Deserialize<'de> for ProductionLoaderPlanV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ProductionLoaderPlanWireV1::deserialize(deserializer)?;
        if wire.schema_version != 1 {
            return Err(serde::de::Error::custom(
                "unsupported production plan schema",
            ));
        }
        if wire.creation_flags != Self::CREATION_FLAGS {
            return Err(serde::de::Error::custom(
                "invalid production creation flags",
            ));
        }
        let expected_digest = wire.launch_plan_sha256;
        let plan = Self::new(ProductionLoaderPlanInputV1 {
            executable_path_utf16: wire.executable_path_utf16,
            executable_sha256: wire.executable_sha256,
            command_line_sha256: wire.command_line_sha256,
            environment: wire.environment,
            current_directory_sha256: wire.current_directory_sha256,
            desktop: wire.desktop,
            process_security_descriptor_sddl: wire.process_security_descriptor_sddl,
            thread_security_descriptor_sddl: wire.thread_security_descriptor_sddl,
            job_security_descriptor_sddl: wire.job_security_descriptor_sddl,
            loader_ready_pipe_security_descriptor_sddl: wire
                .loader_ready_pipe_security_descriptor_sddl,
            target_token: wire.target_token,
            inherited_handles: wire.inherited_handles,
            job_at_creation: wire.job_at_creation,
        })
        .map_err(serde::de::Error::custom)?;
        if plan.launch_plan_sha256 != expected_digest {
            return Err(serde::de::Error::custom("production plan digest mismatch"));
        }
        if plan.process_security_descriptor_sha256 != wire.process_security_descriptor_sha256
            || plan.thread_security_descriptor_sha256 != wire.thread_security_descriptor_sha256
            || plan.job_security_descriptor_sha256 != wire.job_security_descriptor_sha256
            || plan.loader_ready_pipe_security_descriptor_sha256
                != wire.loader_ready_pipe_security_descriptor_sha256
        {
            return Err(serde::de::Error::custom(
                "production security descriptor digest mismatch",
            ));
        }
        Ok(plan)
    }
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_le_bytes());
    target.extend_from_slice(value);
}

fn require_nonempty(field: &'static str, value: &str) -> Result<(), ProductionPlanError> {
    if value.is_empty() {
        Err(ProductionPlanError::Empty { field })
    } else {
        Ok(())
    }
}

fn require_digest(field: &'static str, value: &str) -> Result<(), ProductionPlanError> {
    if value.len() == Sha256::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ProductionPlanError::InvalidDigest { field })
    }
}

fn zero_digest() -> String {
    "0".repeat(Sha256::output_size() * 2)
}
