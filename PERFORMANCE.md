# Performance — measured, not optimised

**Summary: nothing here is slow enough to warrant optimisation, so none was done.**
Inventing a speedup would be its own form of hallucination, so this file reports what
was measured and stops.

All figures: single-threaded CPython 3.11, Apple Silicon, no warm cache.

## lcert-verify — linear, ~1.3 µs per locus

| Loci | Verify | Per locus |
|---|---|---|
| 10 | 0.000 s | 43.9 µs |
| 1,000 | 0.002 s | 1.59 µs |
| 10,000 | 0.014 s | 1.38 µs |
| 100,000 | 0.132 s | 1.32 µs |
| 500,000 | 0.657 s | 1.31 µs |

Cost is linear with a flat per-locus constant; the 10-locus figure is fixed overhead
amortising away. Extrapolating, one million loci is roughly **1.3 s**.

**Implication for scale.** Full-reticle work is 10⁶–10⁸ loci. At this rate 10⁶ is
comfortable and 10⁸ would be ~2 minutes single-threaded — usable, and trivially
parallel across tiles since each certificate verifies independently. No optimisation is
needed for any size we can currently measure.

## equiv-receipt — fast in practice, quadratic in principle

| Instance | Clauses | Lemmas | Check |
|---|---|---|---|
| chain | 5,000 | 1 | 0.8 ms |
| PHP(4,3) | 22 | 17 | <1 ms |
| PHP(5,4) | 45 | 103 | <1 ms |
| PHP(6,5) | 81 | 749 | 50 ms |

`forward_rup_check` rescans the active clause set per lemma, so cost is
**O(clauses × lemmas)**. That is real, and it is honest to state it: at 10⁴ lemmas over
10³ clauses it would be seconds, not milliseconds.

It does not bite today because the bundled `minisolve` cannot reach instances that
large — it raises at its declared depth first. Should anyone check proofs from a real
solver at scale, watched literals are the fix. Until someone does, adding them would be
optimising a path nobody walks.

## prereg-seal — dominated by JSON serialisation

| Keys | Digest |
|---|---|
| 10 | 0.1 ms |
| 1,000 | 2.0 ms |
| 20,000 | 45.6 ms |

Acceptance specifications are tens of keys. This is irrelevant at real sizes.

## cert-atlas

Build 27 cases: **0.01 s**. Score 27 cases: **<0.01 s**. Nothing to optimise.

## What is *not* measured here

Wall-clock of the closed certification engine that *produces* certificates. That is a
different product and a different cost profile; nothing in this repository speaks to it.
