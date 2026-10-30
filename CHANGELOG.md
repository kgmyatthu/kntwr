# Changelog

All notable changes are recorded here. Versions follow `X.Y.Z`; the single source of truth is
`project(kntwr VERSION X.Y.Z)` in `CMakeLists.txt`.

## [Unreleased]

### Added

- `--wounded[=PCT]` (EXPERIMENTAL, opt-in, not part of `--features all`): PCT percent (default 33)
  of shot deaths whose death clip carries a `FACE_DOWN`/`FACE_UP` orientation tag enter the stock
  wounded state (idle/injury/crawl loops) instead of becoming a static corpse. Uses only stock
  clips and the stock wounded state machine; one 8-byte detour at the death state commit.
  Gameplay change: every multiplayer peer must run the same setting.

### Changed

- `--drag-ladder` (60-file drag-out frontage ladder) is now implied by `--features all`;
  `--no-drag-ladder` opts out. Gameplay change: every multiplayer peer must run the same setting.
- `--features all` now implies `cavalry_orbit` (already in the default set); `--no-cavalry-orbit`
  opts out, and listing the exclusive `ai_async2`/`brain2` suppresses the implication.

## [1.0.0] - 2026-10-28

First tagged release.

### Added
- `KNTWR.exe` launcher: starts stock Steam `Napoleon.exe` suspended, applies the gameplay patch in memory, and installs
  `kntwr_runtime.dll`. Game files on disk are never modified; unsupported executables are rejected by SHA-256.
- Game discovery: saved `config.json`, then every Steam library, then an interactive folder picker. `--game`, `--setup`,
  `--check`/`--validate-only`, `--no-launch`, and `--replay` options.
- Multithreaded runtime (`kntwr_runtime.dll`) with the shipping feature set `all,cavalry_orbit`: batched work dispatch
  (batch64), asynchronous AI planning, visual loop sharding, native locomotion with an owned soldier grid, and the soft
  collision solver with contact workers.
- Default-on helpers in the shipping set: tick P-core pinning on hybrid CPUs, bit-exact army solver memoisation, AI
  claim-once and target-cull, mounted officers, cavalry orbit, and allocator/arena release fixes that lower virtual-address
  pressure in large battles.
- Opt-in diagnostics and profiling (`--profile`, `--va-watch`, censuses) that never change simulation results.
- `--version`: prints `KNTWR 1.0.0` and exits before any game lookup.
- Windows VERSIONINFO (company, product, description, file/product version) on `KNTWR.exe` and `kntwr_runtime.dll`.
- Native test suite registered with CTest (oracles against the original game code, synthetic tests, PE/payload audits,
  `kntwr_launcher_version`).
- GitHub Actions CI (build + image-free tests on every push to `main` and pull request) and tag-driven releases with
  `SHA256SUMS.txt` and a build-provenance attestation. Dependabot keeps the workflow actions current.

### Notes
- Binaries are not code signed.
- CI cannot run the `image`/`assets` tests (they need the proprietary game image and local captures); the full suite is run
  locally before each release.

[Unreleased]: https://github.com/kgmyatthu/kntwr/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/kgmyatthu/kntwr/releases/tag/v1.0.0
