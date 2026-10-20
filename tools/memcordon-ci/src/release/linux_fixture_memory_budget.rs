//! Fixture request sizing; production memory accounting remains unchanged.
use memcordon_core::workload_contract_v3::BoundObjectRef;
use memcordon_core::workload_registry_v3::{ImageEntryV1, RuntimeImageDefinitionV1};

#[derive(Clone, Debug, serde::Serialize)]
pub struct FrozenImageMemoryBudget {
    pub runtime_image: BoundObjectRef,
    pub input_image: BoundObjectRef,
    pub page_bytes: u64,
    pub image_bytes: u64,
    pub rounded_image_bytes: u64,
    pub headroom_bytes: u64,
    pub limit_bytes: u64,
}

impl FrozenImageMemoryBudget {
    pub fn for_images(
        runtime: &RuntimeImageDefinitionV1,
        input: &RuntimeImageDefinitionV1,
        expected_runtime: &BoundObjectRef,
        expected_input: &BoundObjectRef,
        page_bytes: u64,
        headroom_bytes: u64,
    ) -> Result<Self, String> {
        if !page_bytes.is_power_of_two() || headroom_bytes == 0 {
            return Err("fixture memory page size/headroom invalid".into());
        }
        let runtime_image = runtime.reference()?;
        let input_image = input.reference()?;
        if &runtime_image != expected_runtime
            || &input_image != expected_input
            || runtime.target != input.target
        {
            return Err("fixture memory images differ from admitted contract".into());
        }
        let mut image_bytes = 0_u64;
        let mut rounded_image_bytes = 0_u64;
        for entry in runtime
            .entries
            .as_slice()
            .iter()
            .chain(input.entries.as_slice())
        {
            if let ImageEntryV1::Regular { size, .. } = entry {
                image_bytes = image_bytes
                    .checked_add(*size)
                    .ok_or("fixture image size overflow")?;
                let pages = size.div_ceil(page_bytes);
                let rounded = pages
                    .checked_mul(page_bytes)
                    .ok_or("fixture image page overflow")?;
                rounded_image_bytes = rounded_image_bytes
                    .checked_add(rounded)
                    .ok_or("fixture image page total overflow")?;
            }
        }
        let limit_bytes = rounded_image_bytes
            .checked_add(headroom_bytes)
            .ok_or("fixture memory budget overflow")?;
        Ok(Self {
            runtime_image,
            input_image,
            page_bytes,
            image_bytes,
            rounded_image_bytes,
            headroom_bytes,
            limit_bytes,
        })
    }

    pub fn token(&self) -> String {
        format!("+{}B", self.limit_bytes)
    }

    pub fn require_maximum(&self, observed: u64) -> Result<(), String> {
        if observed != self.limit_bytes {
            return Err(
                "native memory maximum differs from frozen admitted-image fixture budget".into(),
            );
        }
        Ok(())
    }

    pub fn require_invocation_tokens(
        &self,
        public: Option<&str>,
        completed: Option<&str>,
    ) -> Result<u64, String> {
        let token = public.ok_or("actual fixture invocation memory token absent")?;
        if completed != Some(token) || token != self.token() {
            return Err(
                "actual invocation memory differs from original frozen fixture request".into(),
            );
        }
        let observed = token
            .strip_prefix('+')
            .ok_or("actual fixture memory prefix absent")?
            .parse::<memcordon_core::ByteSize>()
            .map_err(|error| error.to_string())?
            .bytes();
        self.require_maximum(observed)?;
        Ok(observed)
    }
}
