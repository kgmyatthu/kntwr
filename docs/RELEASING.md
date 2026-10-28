# Releasing KNTWR

A release is an annotated `vX.Y.Z` tag on `main`. Pushing the tag runs `.github/workflows/release.yml`, which rebuilds,
re-tests, checks the version, packages, attests, and publishes the GitHub release. Nothing is uploaded by hand.

## 1. Local full-suite gate (manual, required)

CI skips the `image` and `assets` tests because the proprietary game image and local captures are not on GitHub. Run them
locally from a clean configure of the release commit:

```powershell
cmake -S . -B build/release-check -A Win32 -DKNTWR_BUILD_TESTS=ON `
  -DKNTWR_TEST_IMAGE=F:/NTW2/translated_code/analysis/Napoleon_patched.exe `
  -DKNTWR_STOCK_IMAGE="E:/steam/steamapps/common/Napoleon Total War/Napoleon.exe" `
  -DKNTWR_TEST_ASSETS=F:/NTW2/translated_code/analysis
cmake --build build/release-check --config Release --parallel
ctest --test-dir build/release-check -C Release --output-on-failure
```

Every test must pass, and the configure output must not list unexpected "NOT registered (missing input)" tests. Do not
tag with failures, and do not delete or relabel tests to get a pass.

## 2. Bump the version

The version appears in exactly these places:

| Place | Change |
| --- | --- |
| `CMakeLists.txt` | `project(kntwr VERSION X.Y.Z ...)`. This feeds the launcher's `KNTWR_VERSION`, both VERSIONINFO resources, and the `kntwr_launcher_version` test. |
| `CHANGELOG.md` | Move `Unreleased` entries under `## [X.Y.Z] - YYYY-MM-DD`, leave an empty `Unreleased`, update the compare links at the bottom. |
| Examples in `README.md` | Update the example archive filenames if you want them current (documentation only). |

Nothing else hardcodes the version. The release workflow fails if the tag, `KNTWR.exe --version`, and the PE
`ProductVersion` of both binaries disagree.

## 3. Commit and push

```powershell
git add CMakeLists.txt CHANGELOG.md README.md
git commit -m "release: X.Y.Z"
git push origin main
```

## 4. Confirm CI on that commit

Wait for the **CI** workflow on the pushed commit to go green (Actions tab, or `gh run watch`). Do not tag a commit whose
CI is red.

## 5. Tag and push

```powershell
git tag -a vX.Y.Z -m "KNTWR X.Y.Z"
git push origin vX.Y.Z
```

The first release is `v1.0.0`.

## 6. What the workflow produces

For `vX.Y.Z` the **Release** workflow:

1. Configures, builds (MSVC Win32 Release), and runs `ctest -LE "image|assets"`.
2. Verifies `v` + `KNTWR.exe --version` equals the tag and that both binaries' `ProductVersion` match.
3. Runs `tools/package_release.ps1`, producing `artifacts/KNTWR-X.Y.Z-windows-x86.zip`
   (`KNTWR.exe`, `kntwr_runtime.dll`, `README.md`, `CHANGELOG.md`) and `artifacts/SHA256SUMS.txt`.
4. Creates a GitHub build-provenance attestation for the zip.
5. Runs `gh release create vX.Y.Z --title "KNTWR X.Y.Z" --verify-tag --generate-notes` and attaches the zip and
   `SHA256SUMS.txt`.

There is no code-signing certificate, so the binaries are unsigned; the hash and attestation are the integrity story.

To test packaging locally (needs a built tree whose version matches):

```powershell
./tools/package_release.ps1 -Version X.Y.Z -BuildDir build/ci-x86 -OutputDir build/package-test
```

## 7. Reruns and mistakes

- **Transient failure** (runner, network): open the failed run and use *Re-run failed jobs*. A rerun builds the same tag.
- **Tag/version mismatch** (the workflow refuses): fix the commit, then move the tag only if no release exists yet:
  `git tag -d vX.Y.Z`, `git push origin :refs/tags/vX.Y.Z`, re-tag the fixed commit, push again.
- **Release already created but wrong**: delete the GitHub release and the tag, fix, and publish a new patch version
  rather than reusing a version users may already have downloaded.
- **Workflow change needed**: land it on `main` first; a tag runs the workflow definition stored in the tagged commit.
