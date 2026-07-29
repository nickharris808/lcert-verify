# CLI reference

**The command listings below the fold are generated** from the
parser by `gen_cli_docs.py`; a test fails if they are stale. The prose is
hand-written.

```
lcert-verify [BUNDLE_DIR] [EXPECTED_SHA256] [options]
```

## Arguments

| | |
|---|---|
| `BUNDLE_DIR` | Directory containing `bundle.json` and its payload files. |
| `EXPECTED_SHA256` | The **trust anchor** — the bundle fingerprint, obtained out of band. Without it the tool abstains. |

## Options

| Flag | Effect |
|---|---|
| `--no-anchor` | Accept the weaker internal-consistency check on purpose. Verdict becomes `INTERNALLY-CONSISTENT`. |
| `--allow-empty` | Permit a bundle that certifies nothing. |
| `--explain` | Per-locus breakdown: which loci blocked admission, their margin, the margin needed, and the shortfall. |
| `--json` | Machine-readable result. Equivalent to `--format json`. |
| `--format FMT` | Output as `text` (default), `json`, `jsonl`, `sarif`, or `junit`. |
| `-o, --output PATH` | Write the report to a file instead of stdout. |
| `--scope` | Print exactly what is and is not checked. |

## Output formats

```bash
lcert-verify bundle/ "$FP" --format sarif --output lcert.sarif
lcert-verify bundle/ "$FP" --format junit --output results.xml
```

| Format | Use |
|---|---|
| `text` | Human reading. The default. |
| `json` | One object: verdict, errors, fingerprint, counts. |
| `jsonl` | One object per line, for log ingestion. |
| `sarif` | SARIF 2.1.0 — GitHub's Security tab and any code-scanning UI. |
| `junit` | JUnit XML — appears as a test result in essentially any CI. |

**An abstention is never rendered as a pass.** SARIF and JUnit have no "abstained"
state, so `UNVERIFIED` is reported as a **failure with the reason attached** rather
than quietly succeeding — reporting it green would be exactly the confident wrong
answer this tool exists to avoid. The exit code is unchanged by `--format`: a
`--format junit` run that abstains still exits `4`.

## Verdicts

| Verdict | Meaning |
|---|---|
| `VERIFIED` | Anchored, every check passed, and at least one locus carried a proof obligation. |
| `VERIFIED-VACUOUS` | Anchored and consistent, but zero gated loci — nothing had to be earned. |
| `INTERNALLY-CONSISTENT` | Checks passed; anchor deliberately waived. |
| `UNVERIFIED` | **Abstained.** No anchor, so no assertion is possible. Not a failure of the certificate. |
| `VACUOUS` | The bundle certifies nothing. |
| `REFUTED` | A check actually failed. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | `VERIFIED`, `VERIFIED-VACUOUS`, or `INTERNALLY-CONSISTENT` |
| `1` | Refuted by verdict re-derivation |
| `2` | Refuted on integrity: fingerprint, manifest, Merkle root, commitment, canonical form |
| `3` | Vacuous |
| `4` | Unverified — no trust anchor |
| `5` | Usage error |

CI can branch on these: a `4` means "you forgot the anchor", a `2` means "these bytes are
not the artifact you expected", and they warrant different responses.

## The standalone file

`src/lcert_verify/_verifier.py` runs on its own, with no install and no dependencies:

```
python -I -S _verifier.py <bundle_dir> [expected_sha256] [--no-anchor] [--scope]
```

It uses the same exit codes and holds the same line: no anchor means `UNVERIFIED` and
exit `4`, not a pass. A check that actually fails is reported as `FAIL` and exit `1`
whether or not an anchor was given — abstention is for absence of evidence, and a failed
check is evidence.

## Every flag, generated from the parser

<!-- BEGIN GENERATED CLI -->

## Top level

```
usage: lcert-verify [-h] [--no-anchor] [--allow-empty] [--json]
                    [--format {text,json,jsonl,sarif,junit,html}]
                    [--diff OTHER_BUNDLE] [--diff-anchor DIFF_ANCHOR]
                    [-o OUTPUT] [--stream] [--scope] [--explain]
                    [bundle_dir] [expected_sha256]

Re-derive an LCERT-1 certificate's verdict. Abstains rather than asserting
when a trust anchor is absent.

positional arguments:
  bundle_dir
  expected_sha256       bundle fingerprint obtained OUT OF BAND — the trust
                        anchor

options:
  -h, --help            show this help message and exit
  --no-anchor           accept the weaker internal-consistency check on
                        purpose
  --allow-empty         permit a bundle that certifies nothing
  --json                machine-readable output (JSON)
  --format {text,json,jsonl,sarif,junit,html}
                        output format. sarif renders in GitHub code scanning;
                        junit appears in any CI test report; html is a self-
                        contained page with a per-locus margin chart
  --diff OTHER_BUNDLE   compare against another bundle: which certificates
                        changed class and which way the margins moved
  --diff-anchor DIFF_ANCHOR
                        trust anchor for the bundle given to --diff
  -o OUTPUT, --output OUTPUT
                        write the report to this file instead of stdout
  --stream              verify one certificate at a time, for bundles too
                        large to hold in memory. Needs the anchor; gives the
                        same verdict
  --scope               print what is and is not checked
  --explain             show, per locus, which ones prevented admission and by
                        how much

`lcert-verify serve --help` runs it as an HTTP service instead.
```

## `lcert-verify serve`

```
usage: lcert-verify serve [-h] [--host HOST] [--port PORT]

Run the verifier as an HTTP service. Standard library only.

options:
  -h, --help   show this help message and exit
  --host HOST  default is loopback; pass 0.0.0.0 to expose deliberately
  --port PORT
```

<!-- END GENERATED CLI -->

## Python API

| Function | Purpose |
|---|---|
| `verify_bundle(dir, sha="", *, require_certs=True, require_anchor=True)` | Full verification. Returns verdict, ok, trust_anchor, internally_consistent, n_certificates, n_gated_loci, errors, fingerprint. |
| `bundle_fingerprint(dir)` | SHA-256 of `bundle.json` — the value to transport out of band. |
| `explain_certificate(cert, *, limit=20)` | Per-locus classification and margin arithmetic. |
| `format_explanation(exp, *, limit=10)` | Human-readable rendering of the above. |
| `gate_cert(...)`, `make_bundle(...)` | Reference builder, for conformance fixtures. Computes no physics. |
| `rederive_gate_verdict(cert)` | The re-derivation itself. |
| `SCOPE` | The scope statement, verbatim. |
