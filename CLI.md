# CLI reference

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
| `--json` | Machine-readable result. |
| `--scope` | Print exactly what is and is not checked. |

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
