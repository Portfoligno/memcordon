# Microsoft Detours source

Unmodified core source from Microsoft Detours 4.0.1, immutable commit
`e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`:
https://github.com/microsoft/Detours/tree/e4bfd6b03e50de46b47abfbd1e46b384f0c5f833

Archive: https://codeload.github.com/microsoft/Detours/tar.gz/e4bfd6b03e50de46b47abfbd1e46b384f0c5f833

Archive SHA256: `d24f5dd1f977c33301ebd9f3be064e938a7908954df15b31235c9ca6691cb356`.

The complete upstream core source directory and MIT license are retained.
Its Makefile is reference material and is never invoked. Rust build orchestration
uses optional `cc` support only for Windows fixture builds; normal product builds
do not install or call these hooks. AMD64 and ARM64 are supported upstream.
