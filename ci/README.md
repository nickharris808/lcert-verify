# CI integrations

Four ways to run the verifier where your builds already run. All of them share one rule:

**Exit 4 is an abstention, and it fails the build.** No trust anchor means nothing was
established, and a green check on that is exactly the confident wrong answer this tool exists to
prevent. Every snippet here leaves it failing; none of them add `|| true`.

| | File | Notes |
|---|---|---|
| GitHub Actions | [`../action.yml`](../action.yml) | `uses: nickharris808/lcert-verify@main`. Outputs `verdict`, `fingerprint`, `gated-loci`; optional SARIF for the Security tab. |
| pre-commit | [`../.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml) | A hook has nowhere to get an out-of-band anchor, so pass `--no-anchor` and get `INTERNALLY-CONSISTENT` — a weaker and honest claim. The anchored check belongs in CI. |
| GitLab CI | [`gitlab-ci.yml`](gitlab-ci.yml) | Emits JUnit, so the verdict appears in the pipeline's test report. |
| Jenkins | [`Jenkinsfile`](Jenkinsfile) | Same, via `junit`. |

## Where the anchor goes

Not next to the bundle. A bundle carrying its own fingerprint proves nothing — anyone editing the
bundle can recompute it. Put the anchor in a repository variable, a CI secret, or a signed report,
and let the pipeline compare.

## GitHub Actions, in full

```yaml
- uses: nickharris808/lcert-verify@main
  with:
    bundle: certs/my-bundle
    anchor: ${{ vars.LCERT_ANCHOR }}
    sarif: lcert.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: lcert.sarif
```
