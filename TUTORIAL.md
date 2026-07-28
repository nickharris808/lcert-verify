# Tutorial: verifying a certificate you did not produce

Fifteen minutes, no prior context. By the end you will have produced a certificate,
transported it across a trust boundary, verified it as a third party, and watched a
forgery get caught — and one get through, which is the part that matters.

## 0. Install

```
pip install git+https://github.com/nickharris808/lcert-verify.git
```

Nothing needs to be on PyPI, and there is no configuration.

## 1. The problem, concretely

A supplier sends you a mask and says "this is manufacturable, here is the certificate."
What have you learned? That the supplier's tool said so. To check it you would run the
supplier's tool — the same tool, with the same bugs.

A *proof-carrying* certificate is different: it ships the numbers the verdict was
computed from, so you can recompute the verdict yourself.

## 2. Produce one (the supplier's side)

```python
import lcert_verify as L

cert = L.gate_cert(
    "clip_a",
    budget=0.05,          # tolerated failure probability per locus
    safety=1.5,           # safety factor folded into the threshold
    n_photons=100.0,      # photon budget
    thr=0.30,             # resist threshold
    delta_dose=0.02,      # dose tolerance, +/- 2%
    loci=[(0.10, 0.11, 0.05),     # (I_lo, I_hi, ae0) per gated locus
          (0.09, 0.10, 0.04)],
)
L.make_bundle("shipment", gate_certs=[cert], kpis=[], prereg={"budget": 0.05})

print(L.bundle_fingerprint("shipment"))
```

The fingerprint is the one thing that must travel **separately** from the bundle — in a
signed report, an email, a purchase order. Anything the supplier can rewrite alongside
the bundle is not an anchor.

## 3. Verify it (your side)

```
lcert-verify shipment/ <the-fingerprint-you-were-given>
```

```
bundle fingerprint: sha256:...
trust anchor:       fingerprint
certificates:       1  (gated loci: 2)
VERDICT: VERIFIED
```

The verdict was **recomputed** from the certificate's own numbers. It was never read.

## 4. Now break it

Flip the recorded verdict and try again:

```python
import json, pathlib
from lcert_verify import _verifier as V

p = pathlib.Path("shipment/bundle.json")
b = json.loads(p.read_text())
b["gate_certs"][0]["recorded"]["interval_admit"] = False
p.write_bytes(V._canon(b) + b"\n")
```

```
VERDICT: REFUTED
  - [clip_a] recorded interval_admit=False but re-derived True
```

## 5. The forgery that gets through — and why you were told

Now a competent forger edits the *inputs* and recomputes the verdict so the two agree.
Every internal check passes, because the arithmetic is correct — on fabricated numbers.

Verify **without** the fingerprint:

```
lcert-verify shipment/
```

```
trust anchor:       NONE
VERDICT: UNVERIFIED
         (abstained — this is NOT a failure of the certificate, it is a
          refusal to assert without evidence)
```

The tool does not pass it, and does not fail it. It says it cannot tell — because it
cannot. Supply the fingerprint and the same bundle is `REFUTED`.

**This is the whole design.** A verifier that guessed here would be worse than no
verifier, because you would trust its answer.

## 6. When a certificate legitimately fails

```
lcert-verify shipment/ <fingerprint> --explain
```

```
certificate 'clip_a' -> REJECT
  3 loci: 1 safe, 2 unsafe, 0 straddling

  2 locus/loci prevented admission. Worst first:
       idx  class             margin       needed     short by
         1  unsafe           -0.0162     0.138739     0.154939
```

That is actionable: locus 1, short by 0.155 in margin units.

## 7. Where to go next

- **[cert-atlas](https://github.com/nickharris808/cert-atlas)** — score *this* verifier,
  or your own, against 22 labelled forgeries.
- **[equiv-receipt](https://github.com/nickharris808/equiv-receipt)** — the same
  discipline for logic equivalence.
- **[prereg-seal](https://github.com/nickharris808/prereg-seal)** — fix your acceptance
  criteria before you measure.
- **[Try it in a browser](https://huggingface.co/spaces/nickh007/cert-verifier)** — no install.

## What you have *not* established

That the numbers describe your physical design. Nothing here checks physics; see the
honest-scope table in the README.
