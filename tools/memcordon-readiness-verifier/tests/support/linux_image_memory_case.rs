//! Evidence fixture builder, not native execution or budget authority.
pub fn image_fixture_budget(
    owner: &serde_json::Value,
    key: &memcordon_readiness_verifier::CaseKey,
    runtime: &serde_json::Value,
    input: &serde_json::Value,
    contract: &serde_json::Value,
) -> serde_json::Value {
    let page = 4096_u64;
    let sizes = [runtime, input]
        .into_iter()
        .flat_map(|image| image["entries"].as_array().unwrap())
        .filter(|entry| entry["kind"] == "regular")
        .map(|entry| entry["size"].as_u64().unwrap())
        .collect::<Vec<_>>();
    let bytes: u64 = sizes.iter().sum();
    let rounded: u64 = sizes.iter().map(|size| size.div_ceil(page) * page).sum();
    serde_json::json!({"format":"memcordon.linux-fixture-memory-budget","revision":1,
        "source":owner["identity"],"cell":owner["cell"],"lease_id":owner["lease_id"],"key":key,
        "budget":{"runtime_image":contract["runtime_image"],"input_image":contract["input_image"],"page_bytes":page,
        "image_bytes":bytes,"rounded_image_bytes":rounded,"headroom_bytes":512*1024*1024_u64,"limit_bytes":rounded+512*1024*1024_u64}})
}
