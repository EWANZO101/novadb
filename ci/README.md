# CI
`github-actions-ci.yml` is the GitHub Actions workflow (fmt, build, clippy -D warnings, tests,
crash test, cargo-deny, cargo-audit, fuzz smoke).

It lives here because the token used by the build bot has no `workflow` scope, and GitHub
refuses pushes that touch `.github/workflows/`. To enable it (needs a token/user with
`workflow` scope):

    mkdir -p .github/workflows && git mv ci/github-actions-ci.yml .github/workflows/ci.yml

The same steps run locally/in Docker via `docker/run-tests.sh` (the `novadb-builder` image).
