//! Bounded native Git adapter with hooks and executable helpers disabled.
use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use crate::{CiError, Result};

pub struct Git {
    root: PathBuf,
    configuration: tempfile::TempDir,
}

pub struct Tag {
    pub full_ref: String,
    pub object: String,
    pub commit: String,
}

impl Git {
    pub fn new(root: &Path) -> Result<Self> {
        #[cfg(unix)]
        let configuration = tempfile::Builder::new()
            .prefix("memcordon-git-")
            .tempdir_in("/tmp")?;
        #[cfg(not(unix))]
        let configuration = tempfile::Builder::new()
            .prefix("memcordon-git-")
            .tempdir()?;
        std::fs::write(configuration.path().join("config"), b"")?;
        std::fs::create_dir(configuration.path().join("hooks"))?;
        Ok(Self {
            root: root.into(),
            configuration,
        })
    }

    pub fn command(&self, arguments: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Command {
        let mut command = Command::new(if cfg!(windows) { "git.exe" } else { "git" });
        command
            .args(arguments)
            .current_dir(&self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                self.configuration.path().join("config"),
            )
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_COUNT", "7")
            .env("GIT_CONFIG_KEY_0", "core.hooksPath")
            .env(
                "GIT_CONFIG_VALUE_0",
                self.configuration.path().join("hooks"),
            )
            .env("GIT_CONFIG_KEY_1", "credential.helper")
            .env("GIT_CONFIG_VALUE_1", "")
            .env("GIT_CONFIG_KEY_2", "core.askPass")
            .env("GIT_CONFIG_VALUE_2", "")
            .env("GIT_CONFIG_KEY_3", "protocol.ext.allow")
            .env("GIT_CONFIG_VALUE_3", "never")
            .env("GIT_CONFIG_KEY_4", "push.recurseSubmodules")
            .env("GIT_CONFIG_VALUE_4", "no")
            .env("GIT_CONFIG_KEY_5", "http.followRedirects")
            .env("GIT_CONFIG_VALUE_5", "false");
        command
            .env("GIT_CONFIG_KEY_6", "core.fsmonitor")
            .env("GIT_CONFIG_VALUE_6", "false");
        for (name, _) in std::env::vars_os() {
            let text = name.to_string_lossy();
            if text.starts_with("GIT_TRACE")
                || text == "GIT_CURL_VERBOSE"
                || text.starts_with("GIT_CONFIG_KEY_")
                || text.starts_with("GIT_CONFIG_VALUE_")
            {
                // The explicit overrides above remain; clear only inherited keys.
                if !matches!(
                    text.as_ref(),
                    "GIT_CONFIG_KEY_0"
                        | "GIT_CONFIG_VALUE_0"
                        | "GIT_CONFIG_KEY_1"
                        | "GIT_CONFIG_VALUE_1"
                        | "GIT_CONFIG_KEY_2"
                        | "GIT_CONFIG_VALUE_2"
                        | "GIT_CONFIG_KEY_3"
                        | "GIT_CONFIG_VALUE_3"
                        | "GIT_CONFIG_KEY_4"
                        | "GIT_CONFIG_VALUE_4"
                        | "GIT_CONFIG_KEY_5"
                        | "GIT_CONFIG_VALUE_5"
                        | "GIT_CONFIG_KEY_6"
                        | "GIT_CONFIG_VALUE_6"
                ) {
                    command.env_remove(name);
                }
            }
        }
        for name in [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "CARGO_REGISTRY_TOKEN",
            "CARGO_REGISTRIES_CRATES_IO_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_SYSTEM",
            "GIT_EXEC_PATH",
            "GIT_CONFIG",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        ] {
            command.env_remove(name);
        }
        command
    }

    pub fn text(&self, arguments: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Result<String> {
        let mut command = self.command(arguments);
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(120),
            1024 * 1024,
        )?;
        if !output.status.success() {
            return Err(CiError::Message(
                "Git operation failed; no ref mutation retried".into(),
            ));
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| CiError::Message("Git returned non-UTF-8 protocol data".into()))?;
        Ok(text.trim_end_matches(['\r', '\n']).to_owned())
    }

    pub fn require_clean(&self) -> Result<()> {
        if !self
            .text(["status", "--porcelain=v1", "--untracked-files=no"])?
            .is_empty()
        {
            return Err(CiError::Message("tracked checkout/index is dirty".into()));
        }
        Ok(())
    }

    pub fn tags(&self) -> Result<Vec<(String, String)>> {
        let bytes = self.text([
            "for-each-ref",
            "--format=%(refname)%09%(objectname)",
            "refs/tags/",
        ])?;
        bytes
            .lines()
            .map(|line| {
                let (reference, object) = line
                    .split_once('\t')
                    .ok_or_else(|| CiError::Message("invalid Git ref inventory".into()))?;
                super::source::validate_oid(object)?;
                if !reference.starts_with("refs/tags/") {
                    return Err(CiError::Message("invalid full tag ref".into()));
                }
                Ok((reference.into(), object.into()))
            })
            .collect()
    }

    pub fn tag(&self, full_ref: &str) -> Result<Tag> {
        let (reference, object) = self
            .tags()?
            .into_iter()
            .find(|(reference, _)| reference == full_ref)
            .ok_or_else(|| CiError::Message("requested tag does not exist".into()))?;
        let commit = self.text(["rev-list", "--max-count=1", reference.as_str(), "--"])?;
        super::source::validate_oid(&commit)?;
        if self.text(["cat-file", "-t", commit.as_str()])? != "commit" {
            return Err(CiError::Message("tag does not select a commit".into()));
        }
        Ok(Tag {
            full_ref: reference,
            object,
            commit,
        })
    }
}

pub fn create_tag_args(version: &str, commit: &str) -> Vec<OsString> {
    [
        "tag",
        "--annotate",
        "--no-sign",
        "--message",
        "Release",
        "--",
        version,
        commit,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

pub fn push_tag_args(version: &str) -> Vec<OsString> {
    [
        "push",
        "--no-signed",
        "--no-follow-tags",
        "--no-verify",
        "origin",
        "tag",
        version,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}
