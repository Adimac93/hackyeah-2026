//! Human-readable difference between two compiled policies (§4.1): what a
//! security team needs to see before trusting that an upload did what they
//! meant. Works on compiled policies, so a disabled control reads as removed —
//! from the gateway's point of view that is exactly what it is.

use std::collections::BTreeMap;

use serde::Serialize;

use super::{DeterministicControl, Policy, SemanticControl};

/// One line per change: `+` added, `-` removed or disabled, `~` changed.
/// Empty when the two policies enforce the same thing.
pub fn diff(old: &Policy, new: &Policy) -> Vec<String> {
    let mut lines = Vec::new();

    setting(&mut lines, "profile", &old.profile, &new.profile);
    setting(&mut lines, "on_detect", &old.on_detect, &new.on_detect);
    setting(&mut lines, "fail_mode", &old.fail_mode, &new.fail_mode);
    setting(&mut lines, "models", &old.models, &new.models);
    setting(
        &mut lines,
        "pricing",
        &sorted(&old.pricing),
        &sorted(&new.pricing),
    );
    setting(&mut lines, "mcp", &old.mcp, &new.mcp);
    setting(&mut lines, "risk", &old.risk, &new.risk);
    setting(&mut lines, "runaway", &old.runaway, &new.runaway);
    setting(&mut lines, "resources", &old.resources, &new.resources);
    setting(
        &mut lines,
        "signature feed",
        &old.feed.as_ref().map(|f| format!("{}@{}", f.source, f.version)),
        &new.feed.as_ref().map(|f| format!("{}@{}", f.source, f.version)),
    );

    let before = controls(old);
    let after = controls(new);
    for (id, fields) in &after {
        match before.get(id) {
            None => lines.push(format!("+ control {id} ({})", summary(fields))),
            Some(previous) => {
                let changes: Vec<String> = fields
                    .iter()
                    .filter_map(|(name, value)| {
                        let was = previous.get(name).map_or("", String::as_str);
                        (was != value).then(|| format!("{name} {was} -> {value}"))
                    })
                    .collect();
                if !changes.is_empty() {
                    lines.push(format!("~ control {id}: {}", changes.join("; ")));
                }
            }
        }
    }
    for id in before.keys().filter(|id| !after.contains_key(*id)) {
        lines.push(format!("- control {id} (removed or disabled)"));
    }

    lines
}

type Fields = BTreeMap<&'static str, String>;

fn setting<T: Serialize>(lines: &mut Vec<String>, name: &str, old: &T, new: &T) {
    let render = |value: &T| serde_json::to_string(value).unwrap_or_default();
    let (old, new) = (render(old), render(new));
    if old != new {
        lines.push(format!("~ {name}: {old} -> {new}"));
    }
}

fn sorted<V: Clone>(map: &std::collections::HashMap<String, V>) -> BTreeMap<String, V> {
    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

fn controls(policy: &Policy) -> BTreeMap<String, Fields> {
    policy
        .deterministic
        .iter()
        .chain(&policy.signature_controls)
        .map(|c| (c.id.clone(), deterministic(c)))
        .chain(policy.semantic.iter().map(|c| (c.id.clone(), semantic(c))))
        .collect()
}

fn hooks(hooks: &std::collections::HashSet<super::Hook>) -> String {
    let mut names: Vec<String> = hooks
        .iter()
        .map(|h| serde_json::to_string(h).unwrap_or_default().replace('"', ""))
        .collect();
    names.sort();
    names.join(",")
}

fn name<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_default()
        .replace('"', "")
}

fn deterministic(c: &DeterministicControl) -> Fields {
    BTreeMap::from([
        ("kind", "deterministic".to_owned()),
        ("action", name(&c.action)),
        ("severity", name(&c.severity)),
        ("hooks", hooks(&c.hooks)),
        ("pattern", c.regex.as_str().to_owned()),
    ])
}

fn semantic(c: &SemanticControl) -> Fields {
    BTreeMap::from([
        ("kind", "semantic".to_owned()),
        ("action", name(&c.action)),
        ("severity", name(&c.severity)),
        ("hooks", hooks(&c.hooks)),
        ("detector", c.detector.clone()),
        ("threshold", c.threshold.to_string()),
        ("escalate_when", name(&c.escalate_when)),
        ("fail_mode", name(&c.fail_mode)),
    ])
}

fn summary(fields: &Fields) -> String {
    ["kind", "action", "hooks"]
        .iter()
        .filter_map(|key| fields.get(key).cloned())
        .collect::<Vec<_>>()
        .join(", ")
}
