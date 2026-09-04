use std::collections::{BTreeMap, HashSet};

const KNOWN_FAMILIES: [&str; 4] = ["opus", "sonnet", "haiku", "fable"];

pub fn family(model: &str) -> Option<&'static str> {
    let normalized = model.to_ascii_lowercase();
    KNOWN_FAMILIES
        .into_iter()
        .find(|family| normalized.contains(family))
}

pub fn resolve<'a>(mapping: &'a BTreeMap<String, String>, requested: &str) -> Option<&'a str> {
    mapping
        .get(requested)
        .or_else(|| family(requested).and_then(|family| mapping.get(family)))
        .or_else(|| mapping.get("default"))
        .map(String::as_str)
}

pub fn accepted(keys: &HashSet<String>, requested: &str) -> bool {
    keys.is_empty()
        || keys.contains(requested)
        || keys.contains("default")
        || family(requested).is_some_and(|family| keys.contains(family))
}
