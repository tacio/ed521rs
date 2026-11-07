# Releasing

The Rust crate `ed521` and the Python package `ed521rs` are released together, with the same
version. Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which does the following:

1. builds abi3 wheels for Linux (manylinux2014 and musllinux, x86-64 and ARM64), macOS (x86-64
   and Apple silicon) and Windows (x64 and ARM64), plus the sdist;
2. installs the wheels on Linux, macOS and Windows and runs the Python test suite against them;
3. publishes to PyPI and crates.io through trusted publishing (no stored tokens);
4. attests build provenance for the wheels and the sdist, and drafts a GitHub release with them
   attached and the version's `CHANGELOG.md` section as its notes.

## One-time setup

1. **GitHub.** Push the repository to `github.com/tacio/ed521rs` and make it public.
   - Under *Settings → Code security*, enable private vulnerability reporting (SECURITY.md
     points there).
   - Under *Settings → Environments*, create the environments `pypi` and `crates-io`. Adding
     yourself as a required reviewer makes every publish wait for your approval.
2. **PyPI.** Create an account with two-factor authentication. Under *Your account →
   Publishing*, add a pending trusted publisher with these values:

   | Field | Value |
   |---|---|
   | PyPI project | `ed521rs` |
   | Owner | `tacio` |
   | Repository | `ed521rs` |
   | Workflow | `release.yml` |
   | Environment | `pypi` |

   The first tagged release creates the project.
3. **crates.io.** Log in with GitHub and verify your email. crates.io allows trusted publishing
   only for crates that already exist, so publish the first version by hand:
   - Create an API token with the `publish-new` scope, then run `cargo login`.
   - From the release commit, run `cargo publish -p ed521`. The release workflow sees that the
     version exists and skips it.
   - Under the crate's *Settings → Trusted Publishing*, add the repository `tacio/ed521rs` with
     workflow `release.yml` and environment `crates-io`.
   - Revoke the token.

## Each release

1. Set the version in the root `Cargo.toml` (`[workspace.package]`). The Python package reads
   it from there.
2. Move the *Unreleased* notes in `CHANGELOG.md` under a `## [X.Y.Z]` heading. The release
   workflow copies that section into the release notes and fails if it is missing.
3. Run `just check`, plus `just tse-fetch` and `just tse-vectors` if the vectors changed.
4. Commit, then tag and push:

   ```sh
   git tag -s vX.Y.Z -m "ed521rs X.Y.Z"
   git push origin main vX.Y.Z
   ```

   For the first release, run `cargo publish -p ed521` before pushing the tag.
5. Approve the `pypi` and `crates-io` deployments if you made them require review.
6. Review and publish the drafted GitHub release.

A published version can't be replaced on either registry. Fix mistakes in a new patch release;
on crates.io, `cargo yank` keeps new projects from picking up a bad version.
