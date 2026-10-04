use super::*;

#[test]
fn release_configuration_rejects_removed_eligibility_fields() {
    let exact = include_str!("../../../../ci/release.toml");
    toml::from_str::<Release>(exact)
        .expect("branch- and environment-independent release config should parse");
    let exact_table =
        toml::from_str::<toml::Table>(exact).expect("release config should be a TOML table");
    for (obsolete_field, obsolete_value) in [
        (
            "source_branches",
            toml::Value::Array(vec![toml::Value::String("release".to_owned())]),
        ),
        ("environment", toml::Value::String("release".to_owned())),
    ] {
        let mut obsolete_table = exact_table.clone();
        assert!(
            obsolete_table
                .insert(obsolete_field.to_owned(), obsolete_value)
                .is_none()
        );
        let obsolete = toml::to_string(&obsolete_table).expect("release config should serialize");
        assert!(toml::from_str::<Release>(&obsolete).is_err());
    }
}
