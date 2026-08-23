# Sealed provider protocol v1

This is a private local protocol. It is not a stable caller configuration API.

Each frame starts with a 72-byte header: big-endian protocol version (`u16`), message kind (`u16`), total frame length (`u32`), 16-byte request nonce, 16-byte attempt id, and the 32-byte SHA-256 digest of the payload. The remaining bytes are a counted payload. Total length is checked before allocation and is limited to 1 MiB. A digest mismatch rejects the frame before payload interpretation. Transport-derived peer identity and the request nonce provide authentication and replay binding; the digest is an integrity check, not a substitute for peer authentication.

Client kinds are `Probe`, `Launch`, `Cancel`, and `Query`. Provider kinds are `ProbeReceipt`, `LaunchPrepared`, `Authorized`, `Progress`, `Terminal`, and `Rejected`. Unknown versions and kinds are rejected; there is no legacy-parser fallback.

One authenticated request owns one connection. Launch payloads encode the native program, native argument sequence, environment entries, policy, absolute deadline, stream disposition, and descriptor inventory as separately counted values. They never encode a command line or a shell expression. Unix descriptors are transferred out of band and their exact count and purpose must match the payload. Windows stream relays are provider-created and no arbitrary caller handle is accepted.

An `Authorized` receipt is valid only after provider identity, guardian readiness, creation-time boundary assignment, independent assignment readback, inherited-resource verification, spawn-error reporting, and front-end-loss authority are established while the target remains gated or suspended. A `Terminal` receipt is valid only after direct-target accounting, workload emptiness, helper reaping, and irreversible boundary retirement.
