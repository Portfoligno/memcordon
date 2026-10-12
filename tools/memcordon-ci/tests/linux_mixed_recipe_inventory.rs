#![cfg(target_os = "linux")]

use std::{collections::BTreeSet, ffi::OsStr};

use memcordon_ci::release::linux_mixed_installed::owned_fixture_recipes;
use memcordon_readiness_verifier::{EvidenceClass, ProductKey};

#[test]
fn installed_recipe_inventory_has_unique_keys_and_distinct_status_limits() {
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        for channel in ["candidate-native", "candidate-cargo"] {
            let cell = ProductKey {
                target: target.into(),
                channel: channel.into(),
            };
            let recipes = owned_fixture_recipes(&cell).unwrap();
            assert!(!recipes.is_empty() && recipes.len() <= 256);
            let mut keys = BTreeSet::new();
            for recipe in &recipes {
                assert_eq!(recipe.key.target, cell.target);
                assert_eq!(recipe.key.channel.as_deref(), Some(channel));
                assert_eq!(recipe.key.evidence_class, EvidenceClass::InstalledProduct);
                assert!(!recipe.observation_limit.is_zero());
                assert!(
                    keys.insert(recipe.key.clone()),
                    "duplicate recipe {:?}",
                    recipe.key
                );
            }
            for (scenario, limit) in [("deadline", "+2s"), ("memory", "+300s")] {
                let selected = recipes
                    .iter()
                    .filter(|recipe| {
                        recipe.key.family == "C-STATUS" && recipe.key.scenario == scenario
                    })
                    .collect::<Vec<_>>();
                assert_eq!(selected.len(), 1);
                assert_eq!(selected[0].mode, "population-deadline");
                assert_eq!(selected[0].product_deadline, OsStr::new(limit));
            }
        }
    }
}
