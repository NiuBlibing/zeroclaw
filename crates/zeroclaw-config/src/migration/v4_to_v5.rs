//! The V4 → V5 boundary. V4 was released with ZeroClaw 0.9.0.
//!
//! All provider registry and model-route reshaping lives here. Earlier
//! migrations and generation of the released V4 layout remain unchanged.

use anyhow::Result;

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
