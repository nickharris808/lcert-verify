# lcert-verify

[![ci](https://github.com/nickharris808/lcert-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/nickharris808/lcert-verify/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![tests](https://img.shields.io/badge/tests-26%20passing-brightgreen)

**Check a manufacturing certificate without trusting whoever produced it — or installing anything.**

A certificate that only its author can check is a press release. `lcert-verify` re-derives an
LCERT-1 certificate's verdict from the primitive quantities the certificate carries, using
**only the Python standard library**. No numpy. No cryptography package. No network.

```
lcert-verify my_bundle/ <expected-fingerprint>
```

The fingerprint is the **trust anchor**, obtained out of band. Supply it and you get a definite
`VERIFIED` or `REFUTED`. Omit it and you get `UNVERIFIED` — because without an anchor this tool
cannot rule out a forgery in which the inputs and the verdict were edited together, and it will
not pretend otherwise.

## Install

> **Not yet on PyPI.** Install from the repository — it works exactly the same:
>
> ```
> pip install git+https://github.com/nickharris808/lcert-verify.git
> ```

```
pip install lcert-verify
```

Or don't. Copy `src/lcert_verify/_verifier.py` — it is a single self-contained file — and run it.
That is a supported use, and it is the point.

```
python -I -S _verifier.py my_bundle/ <expected_sha256>   # PASS / FAIL
python -I -S _verifier.py my_bundle/                     # UNVERIFIED — abstains, exit 4
```

Because it is a supported path it holds the same line as the installed CLI: with no
expected fingerprint it **abstains** rather than passing. Passing every internal check is
not the same as being the artifact you were promised.

## 30-second quickstart

```python
import lcert_verify as L

cert = L.gate_cert(
    "clip_a",
    budget=0.05, safety=1.5, n_photons=100.0,
    thr=0.30, delta_dose=0.02,
    loci=[(0.10, 0.11, 0.05), (0.09, 0.10, 0.04)],   # (I_lo, I_hi, ae0) per locus
)
L.make_bundle("demo_bundle", gate_certs=[cert],
              kpis=[{"key": "worst_pfail_upper", "value": 0.0041}],
              prereg={"budget": 0.05, "declared": "before measurement"})

fingerprint = L.bundle_fingerprint("demo_bundle")   # publish this out of band
print(L.verify_bundle("demo_bundle", fingerprint)["verdict"])   # VERIFIED
print(L.verify_bundle("demo_bundle")["verdict"])                # UNVERIFIED (no anchor)
```

Then break it, and watch it get caught:

```python
import json, pathlib
import lcert_verify as L
from lcert_verify import _verifier as V

# self-contained: build a bundle, then forge its verdict
cert = L.gate_cert("clip_a", budget=0.05, safety=1.5, n_photons=100.0,
                   thr=0.30, delta_dose=0.02,
                   loci=[(0.10, 0.11, 0.05), (0.09, 0.10, 0.04)])
L.make_bundle("demo_bundle", gate_certs=[cert], kpis=[],
              prereg={"budget": 0.05, "declared": "before measurement"})
fingerprint = L.bundle_fingerprint("demo_bundle")   # captured BEFORE tampering

p = pathlib.Path("demo_bundle/bundle.json")
b = json.loads(p.read_text())
b["gate_certs"][0]["recorded"]["interval_admit"] = False   # forge the verdict
p.write_bytes(V._canon(b) + b"\n")   # rewrite *canonically*, so the forgery is the only defect

res = L.verify_bundle("demo_bundle", fingerprint)
print(res["verdict"])   # REFUTED
print(res["errors"][0]) # [clip_a] recorded interval_admit=False but re-derived True
```

Note the canonical rewrite. A careless edit with `json.dumps` is caught one step earlier, by the
canonical-JSON round-trip — which is itself worth seeing: the format pins byte-level
serialization, so even a whitespace-level edit is a detected modification.

The verdict is never read from the certificate. It is recomputed, per locus, with
outward-rounded interval arithmetic, and compared.

## Why the verdict can be recomputed anywhere

The re-derivation uses only IEEE-754 double `+ - * <`, `max`, and `nextafter`, plus `math.erfc`.
Those operations are correctly rounded by the standard, and CPython floats *are* IEEE doubles, so
a pure-Python re-derivation is bit-identical to the producer's — on any platform. That is why this
verifier can be a few hundred lines and still be exact.


## Documentation

- **[TUTORIAL.md](TUTORIAL.md)** — fifteen minutes, produce → transport → verify → watch a forgery get caught
- **[CLI.md](CLI.md)** — every flag, verdict and exit code, including SARIF and JUnit output
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** — the errors you will actually hit, with fixes
- **[PERFORMANCE.md](PERFORMANCE.md)** — measured, including the optimisation that was deliberately *not* built and why
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — and the portfolio-wide guide it points to

Portfolio-wide: **[Tutorial](https://github.com/nickharris808/certified-oss/blob/main/TUTORIAL.md)**
· **[Concepts](https://github.com/nickharris808/certified-oss/blob/main/CONCEPTS.md)**
· **[FAQ](https://github.com/nickharris808/certified-oss/blob/main/FAQ.md)**
· **[Architecture](https://github.com/nickharris808/certified-oss/blob/main/ARCHITECTURE.md)**
· **[API reference](https://nickharris808.github.io/certified-oss/api/)**


## Beyond a pass/fail

```bash
lcert-verify a/ "$FP_A" --diff b/ --diff-anchor "$FP_B"   # did my change help?
lcert-verify a/ "$FP_A" --format html -o report.html      # per-locus margin chart
```

**`--diff`** compares two bundles: which certificates changed class, which way the margins
moved, what was added or dropped. It exits non-zero only on a regression, so it works as a gate.
Losing admission counts as a regression however the numbers moved, and dropping a certificate
counts too — a bundle that certifies less is not an improvement. If either side does not verify,
the diff says so rather than quietly comparing two documents of unknown provenance.

**`--format html`** writes one self-contained file — no network, no scripts, no dependencies —
with a signed per-locus margin chart. A locus that does not clear the threshold has a negative
margin and its bar points the other way, so the **geometry** carries the meaning; colour only
repeats it. That is deliberate: green and red are the one pair red-green colour blindness
collapses (ΔE 4.1, against a floor of 8), so the bar direction, a hatch fill, a direct text label
and a table view each say it independently. `straddling` — where the enclosure spans the boundary
and neither answer is established — is drawn as its own third state rather than rounded to one
side, and the chart defers to the same `explain` code the verdict comes from, so it cannot
contradict the verdict printed beside it.

## A certificate kind that is not about lithography

`LCERT-BOUND-1` is domain-agnostic: per-locus intervals for any quantity, a threshold, and which
side of it is safe.

```python
cert = L.interval_bound_cert("hotspots", quantity="junction temperature", unit="K",
                             threshold=358.15, direction="below",
                             loci=[(340.0, 351.2), (338.4, 349.9)])
```

The verifier recomputes admission from those numbers. **Overstating your margin is caught;
understating it is allowed**, because conservatism is not a lie. It is re-derived identically by
the JavaScript implementation, and the conformance suite checks the two agree on cases including
a locus exactly on the threshold and one a single ULP inside it.

To produce bundles ergonomically — preregistration, evidence files, self-verification on write —
see **[lcert-build](https://github.com/nickharris808/lcert-build)**.


## Run it as a service

Some teams will not add a Python dependency to a signoff flow but will call an endpoint.

```bash
lcert-verify serve                      # loopback, no dependencies
docker run --rm -p 8080:8080 lcert-verify
curl -H "X-LCERT-Anchor: $ANCHOR" -H 'Content-Type: application/zip' \
     --data-binary @bundle.zip http://localhost:8080/verify
```

**The status code carries the verdict, so a naive caller cannot misread it.** A service that
returned `200` with `{"verdict": "UNVERIFIED"}` would let `if response.ok:` treat an abstention as
a pass — the exact failure this project exists to prevent, in HTTP form.

| Verdict | Status |
|---|---|
| `VERIFIED` · `VERIFIED-VACUOUS` · `INTERNALLY-CONSISTENT` | `200` |
| `UNVERIFIED` | **`428 Precondition Required`** — the anchor is a missing precondition, not a failure of the bundle |
| `REFUTED` · `VACUOUS` | `422 Unprocessable Content` |
| too large · malformed | `413` · `400` — not a verdict at all |

The image is 47 MB, runs as a non-root user, drops all capabilities and mounts its root
filesystem read-only ([`compose.yaml`](compose.yaml)). It logs the verdict and never the payload:
bundles can be confidential and this is meant to drop into an internal network.

## Run it in CI

```yaml
- uses: nickharris808/lcert-verify@main
  with:
    bundle: certs/my-bundle
    anchor: ${{ vars.LCERT_ANCHOR }}
    sarif: lcert.sarif
```

Outputs `verdict`, `fingerprint` and `gated-loci`. **An abstention fails the build by default** —
`allow-abstain` exists and should stay off. There are also [pre-commit hooks](.pre-commit-hooks.yaml)
and [GitLab and Jenkins snippets](ci/README.md). The anchor belongs in a repository variable, not
beside the bundle: a bundle carrying its own fingerprint proves nothing.

## Bundles too large to hold in memory

```bash
lcert-verify big/ "$ANCHOR" --stream
```

Verifies one certificate at a time. On a 22 MB bundle of 100 certificates: **214 MB → 69 MB**
resident, and 899 ms → 548 ms, because it never builds the whole document. On a bundle that is one
enormous certificate it saves only 23% — nothing can stream *inside* a certificate, and
[PERFORMANCE.md](PERFORMANCE.md) says so rather than quoting the flattering row.

It needs the anchor: streaming cannot do the canonical round-trip check, so without a fingerprint
it abstains. With one, byte identity is established exactly, which is strictly stronger.

## Honest scope — what this proves, and what it does not

| Question | Answer |
|---|---|
| Is the artifact internally consistent, and does its verdict follow from its own numbers? | **Yes, always checked.** |
| Was the artifact altered after it was produced, in a way that leaves an inconsistency? | **Yes, always caught.** |
| Was the artifact altered *consistently* — inputs and verdict edited together? | **Only with an out-of-band fingerprint.** Without one this tool returns `UNVERIFIED` and refuses to assert. |
| Do the numbers in it describe your physical design? | **Never checked.** That needs sound enclosures over process models — a separate commercial product. |

The rule this code follows: **when in doubt, refuse.** A verdict of `UNVERIFIED` is not a
failure of your certificate; it is this tool declining to claim something it has not established.

## What is checked — and what is not

Checked: bundle format and canonical-JSON round-trip; the SHA-256 manifest over payload files and
the Merkle root over that manifest (domain-separated leaf/node hashes, HMAC-derived per-leaf salts);
the outputs commitment over reported values and its cross-binding to the pre-registration digest;
the transcendental constants (`kappa` must survive an `erfc` round-trip against the stated budget,
`K` must recompute bit-identically); and the per-locus admission verdict.

**Not checked: the physics.** This verifier confirms that a certificate is internally consistent
and untampered. It does not confirm that the intensity values in it describe your mask, or that the
imaging model behind them is right. Producing a *meaningful* certificate requires the certification
engine, which is not part of this package. Call `python -m lcert_verify.cli --scope` for the exact
statement.

One further honest limit: `bundle.json` cannot self-certify its own bytes in a zero-trust setting —
anyone can recompute an embedded commitment after editing. The verifier prints the bundle
fingerprint and compares it to an expected value **you obtain out of band**. Tampering with the
physics inputs is caught without the fingerprint whenever it flips a re-derived verdict.

## The reference builder

`lcert_verify.builder` emits structurally valid bundles so you can write conformance tests. It
computes no physics — it is a producer of *well-formed* bundles, not of *meaningful* ones.

## License

Apache-2.0. Use it, vendor it, ship it in a commercial product. The format spreading is the goal.

---

## The rest of the toolkit

**A recorded verdict is a claim to be checked, never an input to be trusted.** Nine repositories are built on it.

The whole story, and the objections answered, live at **[certified-oss](https://github.com/nickharris808/certified-oss)** — start there if this is the first one you have opened.

| | |
|---|---|
| [**lcert-verify**](https://github.com/nickharris808/lcert-verify) | Re-derive a manufacturing certificate's verdict. Stdlib only. |
| [**equiv-receipt**](https://github.com/nickharris808/equiv-receipt) | Prove two circuits equivalent, with a receipt anyone can re-check. |
| [**prereg-seal**](https://github.com/nickharris808/prereg-seal) | Seal acceptance criteria before you measure. |
| [**cert-atlas**](https://github.com/nickharris808/cert-atlas) | 21 labelled forgeries and a metric no degenerate verifier can win. |
| [**certified-mcp**](https://github.com/nickharris808/certified-mcp) | The above, as tools your AI agent can call. |
| [**lcert-verify-web**](https://github.com/nickharris808/lcert-verify-web) | The verifier in a browser. Nothing uploaded. |

**Try it now, no install:** [🔏 the verifier Space](https://huggingface.co/spaces/nickh007/cert-verifier) ·
**Browse the forgeries:** [📊 the atlas dataset](https://huggingface.co/datasets/nickh007/cert-atlas)

### Where the free edition stops

Everything here **checks**. None of it **produces** a certificate that is physically meaningful —
that needs sound enclosures over real process models, which is a separate commercial product. If
you need certificates rather than a way to check them, that is the conversation to have.
