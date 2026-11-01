# Microsoft Detours source

Unmodified core source from the Microsoft Detours post-release snapshot still
carrying version 4.0.1, immutable commit
`9764cebcb1a75940e68fa83d6730ffaf0f669401`:
https://github.com/microsoft/Detours/tree/9764cebcb1a75940e68fa83d6730ffaf0f669401

Archive: https://codeload.github.com/microsoft/Detours/tar.gz/9764cebcb1a75940e68fa83d6730ffaf0f669401

Archive SHA256: `6c4397d5eab3372af971b18f5a07d61ad7a61ab7abecbcded4ce5381058e8313`.

Archive SHA512: `30f689a7f7dd3d762f1194ad8d7e05517678b754d6c0db297220f946485a8c8ec8a07cf5f3f893aabcc5623f64c81ee358e2a1c3ba23ba1fbd5856f6b3dd9eb7`.
This immutable revision and SHA512 match Microsoft's vcpkg Detours port.

The complete upstream core source directory and MIT license are retained.
Its Makefile is reference material and is never invoked. Rust build orchestration
uses optional `cc` support only for Windows fixture builds; normal product builds
do not install or call these hooks. AMD64 and ARM64 are supported upstream.
