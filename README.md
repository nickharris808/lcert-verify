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
python -I -S _verifier.py my_bundle/
```

That runs with site-packages disabled and isolated mode on. If it exits `0`, the bundle is
internally consistent, its payload matches its manifest, its Merkle root recomputes, its
outputs commitment binds its reported values, and **its admission verdict was recomputed from
scratch rather than read**.

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

print(L.verify_bundle("demo_bundle")["ok"])        # True
print(L.bundle_fingerprint("demo_bundle"))          # the out-of-band anchor
```

Then break it, and watch it get caught:

```python
import json, pathlib
import lcert_verify as L
from lcert_verify import _verifier as V

p = pathlib.Path("demo_bundle/bundle.json")      # built in the quickstart above
b = json.loads(p.read_text())
b["gate_certs"][0]["recorded"]["interval_admit"] = False      # forge the verdict
p.write_bytes(V._canon(b) + b"\n")   # rewrite *canonically*, so the forgery is the only defect

res = L.verify_bundle("demo_bundle")
print(res["ok"])        # False
print(res["errors"])    # ['[clip_a] recorded interval_admit=False but re-derived True']
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

One idea, six pieces: **a recorded verdict is a claim to be checked, never an input to be trusted.**

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
