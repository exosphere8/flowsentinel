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
   - the OpenAPI snapshot, which carries the version:
     `FLOWSENTINEL_UPDATE_OPENAPI=1 cargo test -p api-server --test openapi`, then
     `npm run gen:api` in `frontend/`;
   - versions in the examples of the README, [installation.md](installation.md), `.env.example`
     and `docker-compose.yml`.

   Then refresh the third-party license notices: `python3 scripts/third_party_licenses.py`. This
   needs `npm ci` in `frontend/`. The release workflow regenerates them for what it builds; the
   committed copy is what local image builds use.
4. **Update [CHANGELOG.md](../CHANGELOG.md):**
   - Move the `Unreleased` entries under `## [X.Y.Z] - YYYY-MM-DD`, dated the day you tag.
   - Under **Changed**, say what users must do.
   - Update the links at the bottom.
5. **Run `python3 scripts/check_release.py --tag vX.Y.Z`** (Python 3.11+). It checks that these
   agree:
   - the versions in `Cargo.toml`, `Cargo.lock`, `package.json`, `package-lock.json` and
     `docs/openapi.json`;
   - the versions in the docs' examples;
   - a changelog section for the version, with a valid date.

   CI runs the same check without `--tag`.
6. **Merge these changes to `main`** through the usual branch and CI.

## Tagging

```sh
git checkout main && git pull
git tag -a vX.Y.Z -m "FlowSentinel X.Y.Z"
git push origin vX.Y.Z
```

The workflow then:

1. Checks the release metadata against the tag.
2. Builds the dashboard and the third-party license notices.
3. Builds the binaries for five targets. Each archive includes the notices and gets a build
   provenance attestation.
4. Builds the container image for `linux/amd64` and `linux/arm64`, each on a native runner. Each
   image is smoke-tested locally before it is pushed, untagged, with an SBOM and provenance.
5. Once every binary and image has passed, publishes:
   - **Image tags:** the two images are tagged as one multi-platform image,
     `ghcr.io/exosphere8/flowsentinel:X.Y.Z` and `:X.Y`, which gets a provenance attestation.
     There is no `latest` tag, so a patch on an older line cannot move it.
   - **The GitHub release:** the changelog section as its notes, the archives, and
     `SHA256SUMS`.

A version with a suffix (`1.0.0-rc.1`) is marked as a pre-release and its image gets only the
`X.Y.Z-suffix` tag.

Steps 1 to 4 also run, without publishing, on branches and pull requests that change what a
release is made from: the workflow, the release scripts, the `Dockerfile`, `Cargo.toml`,
`Cargo.lock`, `CHANGELOG.md` or the dashboard's lock file. They also run on demand from the
**Actions** tab. Check the run for the release-preparation change before tagging.

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

- **The workflow fails before publishing** (any job before **Publish**): nothing is tagged or
  released. Untagged images may have been pushed; they are harmless. Fix the cause on `main`,
  delete the tag (`git push --delete origin vX.Y.Z && git tag -d vX.Y.Z`), and tag again.
- **Publish fails part-way:** check what exists (`gh release view vX.Y.Z`,
  `docker buildx imagetools inspect ghcr.io/exosphere8/flowsentinel:X.Y.Z`), then re-run the
  failed job from the Actions tab.
- **A broken release was published:** do not reuse its version. Mark the GitHub release as a
  pre-release or add a warning to its notes, and release a patch version.
- **A security fix:** follow [../SECURITY.md](../SECURITY.md). Prepare the fix in a private
  security advisory, then release it as a patch version that credits the reporter.
