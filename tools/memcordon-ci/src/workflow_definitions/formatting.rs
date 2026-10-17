//! Presentation choices for the existing serializer, without changing workflow data.
use crate::{CiError, Result};
use serde_yaml::Value;

fn inline(value: &Value) -> Result<String> {
    match value {
        Value::Sequence(items) => Ok(format!(
            "[{}]",
            items
                .iter()
                .map(inline)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        )),
        Value::Mapping(fields) => Ok(format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| {
                    if value.is_null() {
                        Ok(format!("{}:", inline(key)?))
                    } else {
                        Ok(format!("{}: {}", inline(key)?, inline(value)?))
                    }
                })
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        )),
        _ => Ok(serde_json::to_string(value)?),
    }
}

fn mark(value: Option<&mut Value>, replacements: &mut Vec<(String, String)>) -> Result<()> {
    if let Some(value) = value.filter(|value| value.is_sequence()) {
        let marker = format!("MEMCORDON_FLOW_SEQUENCE_{}_END", replacements.len());
        replacements.push((marker.clone(), inline(value)?));
        *value = Value::String(marker);
    }
    Ok(())
}

/// Retain the established flow-style collections; steps and other mapping
/// sequences remain block collections. These are schema paths, not YAML parsing.
fn mark_inline(name: &str, document: &mut Value) -> Result<Vec<(String, String)>> {
    let mut replacements = Vec::new();
    if let Some(inputs) = document
        .get_mut("on")
        .and_then(|events| events.get_mut("workflow_dispatch"))
        .and_then(|dispatch| dispatch.get_mut("inputs"))
        .and_then(Value::as_mapping_mut)
    {
        for input in inputs.values_mut() {
            mark(input.get_mut("options"), &mut replacements)?;
        }
    }
    if name == "release.yml" {
        for field in ["branches", "tags"] {
            mark(document["on"]["push"].get_mut(field), &mut replacements)?;
        }
    }
    if let Some(jobs) = document["jobs"].as_mapping_mut() {
        for (job_name, job) in jobs {
            mark(job.get_mut("needs"), &mut replacements)?;
            if let Some(matrix) = job
                .get_mut("strategy")
                .and_then(|strategy| strategy.get_mut("matrix"))
            {
                if !matrix.is_mapping() {
                    continue;
                }
                mark(matrix.get_mut("shard"), &mut replacements)?;
                let flow_rows = match name {
                    "release.yml" => job_name.as_str() != Some("native-linux-x64"),
                    "backend-certification.yml" => matches!(
                        job_name.as_str(),
                        Some(
                            "windows-payload-x64"
                                | "windows-payload-arm64"
                                | "windows-installed-x64"
                                | "windows-installed-arm64"
                        )
                    ),
                    _ => false,
                };
                if flow_rows {
                    mark(matrix.get_mut("include"), &mut replacements)?;
                }
            }
        }
    }
    Ok(replacements)
}

/// yaml_serde emits indentless block sequences. Add one indentation level for
/// each such sequence, preserving literal/folded scalar contents as scalar data.
fn indent_sequences(yaml: &str) -> String {
    let mut output = String::new();
    let mut sequences = Vec::new();
    let mut scalar = None;
    for line in yaml.lines() {
        let content = line.trim_start_matches(' ');
        let indentation = line.len() - content.len();
        let scalar_body = scalar.is_some_and(|parent| content.is_empty() || indentation > parent);
        if !scalar_body && !content.is_empty() {
            scalar = None;
            let item = content == "-" || content.starts_with("- ");
            while sequences
                .last()
                .is_some_and(|parent| indentation < *parent || (indentation == *parent && !item))
            {
                sequences.pop();
            }
            if item && sequences.last() != Some(&indentation) {
                sequences.push(indentation);
            }
            if content
                .split_once(": ")
                .is_some_and(|(_, value)| matches!(value, "|" | "|-" | "|+" | ">" | ">-" | ">+"))
            {
                scalar = Some(indentation);
            }
        }
        output.push_str(&" ".repeat(sequences.len() * 2));
        // The serializer quotes scalar strings that could look like mapping
        // nulls. Only remove this mapping suffix outside block scalar bodies.
        output.push_str(if scalar_body {
            line
        } else {
            line.strip_suffix(": null").map_or(line, |key| {
                // Retain the colon while omitting the explicit null spelling.
                &line[..key.len() + ":".len()]
            })
        });
        output.push('\n');
    }
    output
}

pub(super) fn serialize(name: &str, document: &Value) -> Result<String> {
    let mut styled = document.clone();
    let replacements = mark_inline(name, &mut styled)?;
    let mut yaml = serde_yaml::to_string(&styled)?;
    for (marker, collection) in replacements {
        yaml = yaml.replace(&marker, &collection);
    }
    let yaml = indent_sequences(&yaml);
    if serde_yaml::from_str::<Value>(&yaml)? != *document {
        return Err(CiError::Message(
            "workflow presentation changed its data".into(),
        ));
    }
    Ok(yaml)
}
