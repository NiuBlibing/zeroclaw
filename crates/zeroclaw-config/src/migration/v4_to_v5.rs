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

    let bindings: Vec<((String, Option<String>), bool)> = root
        .get("agents")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|agents| agents.values())
        .filter_map(toml::Value::as_table)
        .flat_map(|agent| {
            let model_provider = agent
                .get("model_provider")
                .and_then(toml::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let strict = agent
                .get("strict_tool_parsing")
                .and_then(toml::Value::as_bool)
                .unwrap_or_else(|| {
                    agent
                        .get("runtime_profile")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|profile| strict_profiles.contains(profile))
                });
            let mut references = Vec::new();
            if let Some(reference) =
                model_provider.and_then(|reference| legacy_model_selection(models, reference))
            {
                references.push((reference, strict));
            }
            let profile = agent
                .get("runtime_profile")
                .and_then(toml::Value::as_str)
                .and_then(|alias| {
                    root.get("runtime_profiles")
                        .and_then(|profiles| profiles.get(alias))
                });
            if let Some(profile) = profile {
                for route in root
                    .get("model_routes")
                    .and_then(toml::Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let hint = route.get("hint").and_then(toml::Value::as_str);
                    let reachable = profile.get("auto_classify").and_then(toml::Value::as_bool)
                        == Some(true)
                        || profile.get("effort_routing").is_some_and(|routing| {
                            ["local_hint", "cloud_hint"].iter().any(|field| {
                                routing.get(*field).and_then(toml::Value::as_str) == hint
                                    && hint.is_some()
                            })
                        });
                    if reachable
                        && let Some(reference) = route
                            .get("model_provider")
                            .and_then(toml::Value::as_str)
                            .and_then(|reference| legacy_model_selection(models, reference))
                    {
                        references.push((reference, strict));
                    }
                }
            }
            references
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
        let reference = reference.0;
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
        let (reference, model_alias) = reference;
        let (family, alias) = reference
            .split_once('.')
            .context("legacy provider reference must contain a family and alias")?;
        let profile = models
            .get_mut(family)
            .and_then(toml::Value::as_table_mut)
            .and_then(|family| family.get_mut(alias))
            .and_then(toml::Value::as_table_mut)
            .with_context(|| format!("legacy model_provider {reference} is missing"))?;
        let target = if let Some(model_alias) = model_alias {
            profile
                .get_mut("models")
                .and_then(toml::Value::as_table_mut)
                .and_then(|entries| entries.get_mut(&model_alias))
                .and_then(toml::Value::as_table_mut)
                .with_context(|| {
                    format!("legacy model_provider {reference}.{model_alias} is missing")
                })?
        } else {
            profile
        };
        let provider_extra = target
            .entry("provider_extra")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let Some(provider_extra) = provider_extra.as_table_mut() else {
            bail!(
                "cannot migrate strict_tool_parsing for {reference}: provider_extra must be a table"
            );
        };
        provider_extra.insert(
            "__zeroclaw_migration_extract_text_tool_calls".into(),
            toml::Value::Boolean(false),
        );
    }
    Ok(())
}

fn legacy_model_selection(
    models: &toml::Table,
    model_provider: &str,
) -> Option<(String, Option<String>)> {
    let (family, alias) = model_provider.split_once('.')?;
    let family_table = models.get(family)?.as_table()?;
    if family_table.contains_key(alias) {
        return Some((format!("{family}.{alias}"), None));
    }
    // Dotted aliases are TOML keys, not path separators. Resolve the longest
    // configured alias prefix before treating the remaining suffix as a
    // historical model selector.
    let mut candidate = alias;
    while let Some((prefix, _)) = candidate.rsplit_once('.') {
        candidate = prefix;
        if family_table.contains_key(candidate) {
            let suffix = alias.strip_prefix(candidate)?.strip_prefix('.')?;
            let profile = family_table.get(candidate)?.as_table()?;
            let entries = profile.get("models")?.as_table()?;
            return entries
                .contains_key(suffix)
                .then(|| (format!("{family}.{candidate}"), Some(suffix.to_owned())));
        }
    }
    None
}

#[cfg(test)]
fn legacy_profile_reference(models: &toml::Table, model_provider: &str) -> Option<String> {
    legacy_model_selection(models, model_provider).map(|(reference, _)| reference)
}

pub(super) fn migrate(value: toml::Value) -> Result<toml::Value> {
    let mut value = value;
    migrate_profile_fallbacks(&mut value)?;
    let value = super::model_routes::migrate(value)?;
    // Typed registry materialization follows admission so malformed provider
    // aliases can still use the established section-by-section salvage path.
    super::stamp_schema_version(value, 5)
}

/// Convert the V4 profile-local fallback lists before the retirement pass
/// removes those fields. The canonical registry stores exact model references
/// in one graph, so both a provider reference and a same-family model id are
/// resolved to the corresponding opaque key when possible.
fn migrate_profile_fallbacks(value: &mut toml::Value) -> Result<()> {
    let Some(root) = value.as_table_mut() else {
        return Ok(());
    };
    let Some(providers) = root
        .get_mut("providers")
        .and_then(toml::Value::as_table_mut)
    else {
        return Ok(());
    };
    let Some(models) = providers.get("models").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    let mut additions = Vec::<(String, Vec<String>)>::new();
    let mut generated = toml::Table::new();
    for (family, family_value) in models {
        if family_value.get("capability").is_some() {
            continue;
        }
        let Some(family_table) = family_value.as_table() else {
            continue;
        };
        for (alias, profile_value) in family_table {
            let Some(profile) = profile_value.as_table() else {
                continue;
            };
            let source = format!("{family}.{alias}");
            let mut targets = Vec::new();
            let raw = serde_json::to_value(profile)?;
            // Raw upstream IDs retain this profile's connection and tuning.
            // Dedicated graph nodes avoid cycles when a named model is also
            // listed as a fallback and inherits the profile's fallback list.
            for model_id in profile
                .get("fallback_models")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
            {
                if targets.iter().any(|target: &String| {
                    generated
                        .get(target)
                        .and_then(|model| model.get("model"))
                        .and_then(toml::Value::as_str)
                        == Some(model_id)
                }) {
                    continue;
                }
                let base = format!("fallback.{source}.{model_id}");
                let mut reference = base.clone();
                let mut suffix = 1;
                while models.contains_key(&reference) || generated.contains_key(&reference) {
                    reference = format!("{base}.{suffix}");
                    suffix += 1;
                }
                let (_, mut model) =
                    super::model_routes::legacy_model(&raw, family, None, Some(model_id))?;
                model["provider"] = format!("legacy.{source}").into();
                generated.insert(reference.clone(), toml::Value::try_from(model)?);
                targets.push(reference);
            }
            // V4 exhausted same-connection models before switching providers.
            for fallback in profile
                .get("fallback")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(str::trim)
                .filter(|reference| !reference.is_empty())
            {
                let target = if fallback.contains('.') {
                    fallback.to_owned()
                } else {
                    format!("{family}.{fallback}")
                };
                if target != source && !targets.contains(&target) {
                    targets.push(target);
                }
            }
            if !targets.is_empty() {
                // Every original named selection used the enclosing profile's
                // fallback policy. Generated fallback nodes have no outgoing
                // edges; their ordered siblings remain on each source node.
                if let Some(entries) = profile.get("models").and_then(toml::Value::as_table) {
                    for name in entries.keys() {
                        additions.push((format!("{source}.{name}"), targets.clone()));
                    }
                }
                additions.push((source, targets));
            }
        }
    }
    providers
        .get_mut("models")
        .and_then(toml::Value::as_table_mut)
        .context("providers.models must be a table")?
        .extend(generated);
    if additions.is_empty() {
        return Ok(());
    }
    let fallback = providers
        .entry("fallback")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .context("providers.fallback must be a table")?;
    for (source, targets) in additions {
        let entry = fallback
            .entry(source)
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .context("providers.fallback entries must be arrays")?;
        for target in targets {
            if !entry
                .iter()
                .any(|value| value.as_str() == Some(target.as_str()))
            {
                entry.push(toml::Value::String(target));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{GenerateOptions, generate, migrate_file};
    use super::legacy_profile_reference;

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
    fn strict_nested_model_binding_preserves_text_tool_opt_out() {
        let input = r#"
schema_version = 4

[providers.models.ollama.main]
model = "llama3"
[providers.models.ollama.main.models.fast]
id = "llama3-fast"

[agents.worker]
model_provider = "ollama.main.fast"
runtime_profile = "strict"

[runtime_profiles.strict]
strict_tool_parsing = true
"#;
        let output = migrate_file(input).unwrap().unwrap();
        let value: toml::Value = toml::from_str(&output).unwrap();
        assert_eq!(
            value["providers"]["models"]["ollama.main.fast"]["options"]["extract_text_tool_calls"]
                .as_bool(),
            Some(false)
        );
        assert!(!output.contains("strict_tool_parsing"));
    }

    #[test]
    fn fallback_model_ids_are_materialized_before_provider_fallbacks() {
        let input = r#"
schema_version = 4

[providers.models.openai.main]
model = "gpt-4o"
fallback_models = ["gpt-4o-mini"]
fallback = ["openai.backup"]

[providers.models.openai.backup]
model = "gpt-4o-backup"
"#;
        let output = migrate_file(input).unwrap().unwrap();
        let value: toml::Value = toml::from_str(&output).unwrap();
        assert_eq!(
            value["providers"]["models"]["openai.main"]["model"].as_str(),
            Some("gpt-4o")
        );
        assert_eq!(
            value["providers"]["models"]["fallback.openai.main.gpt-4o-mini"]["model"].as_str(),
            Some("gpt-4o-mini")
        );
        assert_eq!(
            value["providers"]["fallback"]["openai.main"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>(),
            vec!["fallback.openai.main.gpt-4o-mini", "openai.backup"]
        );
    }

    #[test]
    fn legacy_strict_profile_lookup_uses_longest_exact_toml_key() {
        let models: toml::Value = toml::from_str(
            r#"
[ollama.main]
[ollama.main.models.fast]
[ollama."main.us"]
[ollama."main.us".models.fast]
"#,
        )
        .unwrap();
        for (input, expected) in [
            ("ollama.main.fast", Some("ollama.main")),
            ("ollama.main.us.fast", Some("ollama.main.us")),
            ("ollama.main.us", Some("ollama.main.us")),
            ("ollama.unknown.fast", None),
        ] {
            assert_eq!(
                legacy_profile_reference(models.as_table().unwrap(), input).as_deref(),
                expected,
                "{input}"
            );
        }
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
