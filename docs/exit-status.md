# Exit status

| Status | Meaning |
|---:|---|
| child code | An ordinary direct-child exit, preserved unchanged. |
| `124` | Workload memory limit reached. |
| `125` | Wrapper, backend, monitoring, required reporting, or cleanup failure. |
| `126` | Command found but not executable. |
| `127` | Command not found. |
| `2` | CLI usage or configuration error before launch. |
| `128 + signal` | Unix signal termination without a higher-precedence event. |

Precedence is limit, monitor failure, wrapper interruption, child signal, then
ordinary child exit. JSON reports distinguish a child that independently
returns one of the reserved values.

