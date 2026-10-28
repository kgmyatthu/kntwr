# KNTWR

KNTWR (Kaung's Napoleon Total War Runtime) is a native multithreading launcher and runtime for **Napoleon: Total War**.
`KNTWR.exe` starts the game suspended, applies an in-memory gameplay patch, injects `kntwr_runtime.dll`, and lets the
runtime run selected parts of the battle simulation (pathing, movement, collision, AI planning, rendering preparation) on
worker threads. Nothing on disk is modified: your game files stay stock.

## Requirements

- Windows, x86 or x64 (the launcher and runtime are 32-bit, like the game).
- The **stock Steam** `Napoleon.exe` (SHA-256 `44880ec1770f600163a336eec83b4366901484c5cceec83dc326e2932f02a054`).
  Modified, cracked, or pre-patched executables are rejected. If in doubt, use Steam > Properties > Installed Files >
  Verify integrity of game files.
- No game files are shipped here.

## Quick start

1. Download `KNTWR-X.Y.Z-windows-x86.zip` from [Releases](../../releases) and verify it (below).
2. Extract `KNTWR.exe` and `kntwr_runtime.dll` into the **same** folder (any folder; they do not go into the game folder).
3. Run `KNTWR.exe`. It finds the game through the saved configuration, then your Steam libraries; if nothing is found it
   opens a folder picker and remembers the choice in `config.json` next to `KNTWR.exe`.
4. The default is the shipping feature set (`--features all,cavalry_orbit`). `KNTWR.exe --help` lists every option;
   `KNTWR.exe --version` prints the version; `KNTWR.exe --check` is a read-only environment check.

Run `KNTWR.exe --console` to see launcher output in a console window.

## Verify a download

Each release contains `KNTWR-X.Y.Z-windows-x86.zip` and `SHA256SUMS.txt` (lowercase hex, two spaces, filename).

```powershell
(Get-FileHash .\KNTWR-1.0.0-windows-x86.zip -Algorithm SHA256).Hash.ToLowerInvariant()
Get-Content .\SHA256SUMS.txt
```

The two hashes must match. Release archives also carry a GitHub build-provenance attestation, which ties the file to the
workflow run that built it:

```powershell
gh attestation verify .\KNTWR-1.0.0-windows-x86.zip --repo kgmyatthu/kntwr
```

## Build

Requires Visual Studio with the MSVC x86 toolset and CMake 3.21 or newer. Only MSVC / Win32 / Release is supported.

```powershell
cmake -S . -B build -A Win32 -DKNTWR_BUILD_TESTS=ON
cmake --build build --config Release --parallel
```

Outputs: `build/bin/Release/KNTWR.exe` and `build/bin/Release/kntwr_runtime.dll`. Presets for Ninja
(run from an x86 developer shell) and Visual Studio 2026 are in `CMakePresets.json`.

## Tests

```powershell
ctest --test-dir build -C Release --output-on-failure -LE "image|assets"
```

That is exactly what GitHub Actions runs: the self-contained native, synthetic, and audit tests. It needs no game data.

The other tests (labels `image` and `assets`) compare the port against the original game machine code and pinned
captures, so they need the private inputs that cannot be hosted here:

```powershell
cmake -S . -B build -A Win32 -DKNTWR_BUILD_TESTS=ON `
  -DKNTWR_TEST_IMAGE=<patched pinned image> -DKNTWR_STOCK_IMAGE=<stock Napoleon.exe> -DKNTWR_TEST_ASSETS=<captures dir>
ctest --test-dir build -C Release --output-on-failure
```

Tests whose input is missing are not registered, never registered as passing. CI is therefore a build-and-self-test gate;
the full image suite is a manual release prerequisite (see [docs/RELEASING.md](docs/RELEASING.md)).

## Safety and antivirus

KNTWR creates the game process suspended, patches it in memory, and loads a DLL into it. Tools that do this resemble what
some antivirus products flag, and the binaries are **not code signed**. Verify the hash and attestation, build from source
if you prefer, and add an exclusion only for the folder you trust. It does not touch your game files, but use it at your
own risk.

## Changes and releases

See [CHANGELOG.md](CHANGELOG.md). Release procedure: [docs/RELEASING.md](docs/RELEASING.md).
