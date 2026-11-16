//! The V4 → V5 boundary. V4 was released with ZeroClaw 0.9.0.
//!
//! All provider registry and model-route reshaping lives here. Earlier
//! migrations and generation of the released V4 layout remain unchanged.

use anyhow::{Context, Result, bail};

/// Preserve the V4 agent/runtime-profile text-tool parsing policy before the
/// V5 retirement pass removes the old key. The V5 parser policy belongs to the
/// canonical chat model, so a strict binding is projected onto its legacy
/// provider profile and is carried through the normal provider admission.
pub(super) fn preserve_strict_tool_parsing(value: &mut toml::Value) -> Result<()> {
    let Some(root) = value.as_table_mut() else {
        return Ok(());
    };
    let strict_profiles: std::collections::HashSet<String> = root
        .get("runtime_profiles")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|profiles| profiles.iter())
        .filter_map(|(name, profile)| {
            profile
                .get("strict_tool_parsing")
                .and_then(toml::Value::as_bool)
                .filter(|strict| *strict)
                .map(|_| name.clone())
        })
        .collect();

    let Some(models) = root
        .get("providers")
        .and_then(|providers| providers.get("models"))
        .and_then(toml::Value::as_table)
    else {
        return Ok(());
    };

    let bindings: Vec<(String, bool)> = root
        .get("agents")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|agents| agents.values())
        .filter_map(toml::Value::as_table)
        .filter_map(|agent| {
            let model_provider = agent
                .get("model_provider")
                .and_then(toml::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())?;
            let reference = legacy_profile_reference(models, model_provider)?;
            let strict = agent
                .get("strict_tool_parsing")
                .and_then(toml::Value::as_bool)
                .unwrap_or_else(|| {
                    agent
                        .get("runtime_profile")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|profile| strict_profiles.contains(profile))
                });
            Some((reference, strict))
        })
        .collect();

    let mut strict_refs = std::collections::HashSet::new();
    let mut non_strict_refs = std::collections::HashSet::new();
    for (reference, strict) in bindings {
        if strict {
            strict_refs.insert(reference);
        } else {
            non_strict_refs.insert(reference);
        }
    }

    let mixed: Vec<_> = strict_refs
        .intersection(&non_strict_refs)
        .cloned()
        .collect();
    if let Some(reference) = mixed.into_iter().next() {
        bail!(
            "cannot migrate V4 strict_tool_parsing for model_provider {reference}: it is used by both strict and non-strict agents; set model options.extract_text_tool_calls explicitly for separate model references and retry"
        );
    }

    let Some(providers) = root
        .get_mut("providers")
        .and_then(toml::Value::as_table_mut)
    else {
        return Ok(());
    };
    let Some(models) = providers
        .get_mut("models")
        .and_then(toml::Value::as_table_mut)
    else {
        return Ok(());
    };
    for reference in strict_refs {
        let (family, alias) = reference
            .split_once('.')
            .context("legacy provider reference must contain a family and alias")?;
        let profile = models
            .get_mut(family)
            .and_then(toml::Value::as_table_mut)
            .and_then(|family| family.get_mut(alias))
            .and_then(toml::Value::as_table_mut)
            .with_context(|| format!("legacy model_provider {reference} is missing"))?;
        let options = profile
            .entry("extract_text_tool_calls")
            .or_insert_with(|| toml::Value::Boolean(false));
        if !options.is_bool() {
            bail!(
                "cannot migrate strict_tool_parsing for {reference}: extract_text_tool_calls must be a boolean"
            );
        }
        *options = toml::Value::Boolean(false);
    }
    Ok(())
}

fn legacy_profile_reference(models: &toml::Table, model_provider: &str) -> Option<String> {
    let (family, alias) = model_provider.split_once('.')?;
    let family_table = models.get(family)?.as_table()?;
    if family_table.contains_key(alias) {
        return Some(format!("{family}.{alias}"));
    }
    // Dotted aliases are TOML keys, not path separators. Resolve the longest
    // configured alias prefix before treating the remaining suffix as a
    // historical model selector.
    let mut candidate = alias;
    while let Some((prefix, _)) = candidate.rsplit_once('.') {
        if family_table.contains_key(candidate) {
            return Some(format!("{family}.{candidate}"));
        }
        candidate = prefix;
    }
    None
}

pub(super) fn migrate(value: toml::Value) -> Result<toml::Value> {
    let value = super::model_routes::migrate(value)?;
    // Typed registry materialization follows admission so malformed provider
    // aliases can still use the established section-by-section salvage path.
    super::stamp_schema_version(value, 5)
}

#[cfg(test)]
mod tests {
    use super::super::{GenerateOptions, generate, migrate_file};

    #[test]
    fn released_v4_generation_stays_frozen() {
        assert_eq!(
            generate(4, &GenerateOptions::default()).unwrap(),
            include_str!("../../fixtures/v4.toml"),
        );
    }

    #[test]
    fn v4_provider_profiles_become_v5_connections_and_models() {
        let input = "schema_version = 4\n\n[providers.models.openai.main]\napi_key = 'enc2:TEST_CIPHERTEXT'\nmodel = 'gpt-4o'\n\n[tools]\noptional = ['*']\n";
        let output = migrate_file(input).unwrap().unwrap();
        let value: toml::Value = toml::from_str(&output).unwrap();
        assert_eq!(value["schema_version"].as_integer(), Some(5));
        assert!(value["providers"].get("connections").is_some());
        assert_eq!(
            value["providers"]["models"]["openai.main"]["model"].as_str(),
            Some("gpt-4o")
        );
        assert!(output.contains("enc2:TEST_CIPHERTEXT"));
        assert!(value["providers"]["models"].get("openai").is_none());
        assert!(migrate_file(&output).unwrap().is_none());
    }

    #[test]
    fn strict_runtime_profile_becomes_model_text_tool_opt_out() {
        let input = r#"
schema_version = 4

[providers.models.openai.main]
api_key = "test-key"
model = "gpt-4o"

[agents.worker]
model_provider = "openai.main"
runtime_profile = "strict"

[runtime_profiles.strict]
strict_tool_parsing = true
"#;
        let output = migrate_file(input).unwrap().unwrap();
        let value: toml::Value = toml::from_str(&output).unwrap();
        assert_eq!(
            value["providers"]["models"]["openai.main"]["options"]["extract_text_tool_calls"]
                .as_bool(),
            Some(false)
        );
        assert!(!output.contains("strict_tool_parsing"));
    }

    #[test]
    fn strict_and_non_strict_agents_sharing_a_model_are_rejected() {
        let input = r#"
schema_version = 4

[providers.models.openai.main]
api_key = "test-key"
model = "gpt-4o"

[agents.strict]
model_provider = "openai.main"
runtime_profile = "strict"

[agents.default]
model_provider = "openai.main"

[runtime_profiles.strict]
strict_tool_parsing = true
"#;
        let error = migrate_file(input).unwrap_err().to_string();
        assert!(
            error.contains("both strict and non-strict agents"),
            "{error}"
        );
    }

    #[test]
    fn malformed_v4_provider_does_not_discard_unrelated_config_during_salvage() {
        let input = "schema_version = 4\nlocale = 'fr'\n\n[security]\ntrust_daemon_uid = false\n\n[providers.models.openai.main]\napi_key = 123\n";
        assert!(super::super::migrate_to_current(input).is_err());
        let load = super::super::migrate_to_current_salvaged(input);
        assert_eq!(load.config.schema_version, 5);
        assert_eq!(load.config.locale.as_deref(), Some("fr"));
        assert!(!load.config.security.trust_daemon_uid);
        assert!(load.dropped_security.is_empty());
    }

    #[test]
    fn older_versions_reach_v5_through_the_chain() {
        for version in 1..=4 {
            let source = generate(version, &GenerateOptions::default()).unwrap();
            let output = migrate_file(&source).unwrap().unwrap();
            let value: toml::Value = toml::from_str(&output).unwrap();
            assert_eq!(value["schema_version"].as_integer(), Some(5));
            assert!(migrate_file(&output).unwrap().is_none());
        }
    }
}
