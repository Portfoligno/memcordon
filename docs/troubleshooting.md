# Troubleshooting

## Hard enforcement is unavailable

Run `memcordon probe`. macOS intentionally offers watchdog enforcement only.
This build also reports the Linux and Windows strong backends as not enabled
rather than silently downgrading.

## A watchdog misses a burst

Sampling is not a hard cap. Shorter intervals increase overhead and values below
10ms are rejected.

## Status 125

This indicates wrapper, monitor, reporting, or incomplete-cleanup failure. Use a
JSON report to inspect the cleanup summary and backend limitations.

## Background processes

The default `--lifetime command` kills remaining known descendants when the
direct child exits. `--lifetime workload` waits for natural workload emptiness
and has a bounded safety deadline.

