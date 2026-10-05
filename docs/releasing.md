# Releasing

This guide is for maintainers. Releases are cut from `main` by pushing a tag `vX.Y.Z`. The
[release workflow](../.github/workflows/release.yml) builds, attests and publishes everything,
and refuses to run if versions or the changelog disagree.

## Versioning

FlowSentinel uses [Semantic Versioning](https://semver.org/). Before 1.0.0:

- a minor release (0.2.0) may change the API, configuration or database schema;
- a patch release (0.1.1) fixes bugs only.

Every release's database migrations run automatically on start, so a newer server can read an
older database. Migrations are never edited once released.

## Before the release

1. **CI must be green on `main`**: every job of the CI and CodeQL workflows.
2. **Run the checks CI cannot run:**
   - fuzz targets touched since the last release, for at least 10 minutes each
     ([../fuzz/README.md](../fuzz/README.md));
   - `cargo bench -p analysis` and `scripts/load_test.py`, compared with
     [performance.md](performance.md) (update its numbers if they changed);
   - a live capture on a real interface with the container image ([live-capture.md](live-capture.md)).
3. **Bump the version** everywhere:
   - the workspace version in `Cargo.toml`, then `cargo update -w` to update `Cargo.lock`;
   - `npm version X.Y.Z --no-git-tag-version` in `frontend/`;
   - versions in the examples of [installation.md](installation.md), `.env.example` and
     `docker-compose.yml`.
4. **Update [CHANGELOG.md](../CHANGELOG.md):**
   - Move the `Unreleased` entries under `## [X.Y.Z] - YYYY-MM-DD`, dated the day you tag.
   - Under **Changed**, say what users must do.
   - Update the links at the bottom.
5. **Run `python3 scripts/check_release.py --tag vX.Y.Z`.** It checks that the versions in
   `Cargo.toml`, `Cargo.lock`, `package.json` and `package-lock.json` agree, and that the
   changelog has a dated section for the version.
6. **Merge these changes to `main`** through the usual branch and CI.

## Tagging

```sh
git checkout main && git pull
git tag -a vX.Y.Z -m "FlowSentinel X.Y.Z"
git push origin vX.Y.Z
```

The workflow then:

1. Checks the release metadata against the tag.
2. Builds the dashboard and the binaries for five targets. Each archive gets a build provenance
   attestation.
3. Builds the container image and pushes it to `ghcr.io/exosphere8/flowsentinel:X.Y.Z` and
   `:X.Y`, with an SBOM and provenance. It then smoke-tests the pushed image.
4. Creates the GitHub release:
   - the changelog section, as notes;
   - the archives;
   - `SHA256SUMS`.

A version with a suffix (`1.0.0-rc.1`) is marked as a pre-release.

Changes to the workflow, `scripts/check_release.py` or the `Dockerfile` run steps 1 to 3 on
branches and pull requests without publishing. Check those runs before tagging.

## After the release

- **Check the published release:**
  - Download an archive, then verify it with `sha256sum -c SHA256SUMS --ignore-missing` and
    `gh attestation verify FILE --repo exosphere8/flowsentinel`.
  - Run [installation.md](installation.md) against the published image.
- **Container package visibility.** On the first release, make sure the package is public: on
  GitHub, open **Packages → flowsentinel → Package settings → Change visibility**. Container
  packages can start private even when the repository is public.
- **Start the next cycle:** add an empty `## [Unreleased]` section to the changelog if it is
  missing.

## If something goes wrong

- **The workflow fails before publishing:** fix the cause on `main`, delete the tag
  (`git push --delete origin vX.Y.Z && git tag -d vX.Y.Z`), and tag again.
- **A broken release was published:** do not reuse its version. Mark the GitHub release as a
  pre-release or add a warning to its notes, and release a patch version.
- **A security fix:** follow [../SECURITY.md](../SECURITY.md). Prepare the fix in a private
  security advisory, then release it as a patch version that credits the reporter.
