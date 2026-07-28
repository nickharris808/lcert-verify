# Performance — measured, not projected

**One optimisation has been made, and it is reported below with the before and after
from an actual run of both versions.** Everything else measured here is fast enough
that optimising it would be optimising a path nobody walks; inventing a speedup would
be its own form of hallucination, so the rest of this file reports what was measured
and stops.

All figures: single-threaded CPython 3.11, Apple Silicon, no warm cache.

## The one optimisation: parse `bundle.json` once, not four times

The hardening pass added three helpers — `_count_certs`, `_count_gated_loci`,
`_nonfinite_fields` — each of which re-opened and re-parsed the bundle the raw verifier
had already parsed. Four `json.loads` of a multi-megabyte document per verification.

The fix threads the parsed object through: the helpers now take a dict, and the frozen
verifier returns the bundle it parsed under a private `_parsed` key that the public
wrapper strips before returning.

Measured by running **both versions**, each in its own interpreter, over the same
bundle. Median of 15 reps at 200k loci and 9 at the other sizes:

| Loci | bundle.json | Before | After | Saving | Speedup |
|---|---|---|---|---|---|
| 50,000 | 1.4 MB | 81.4 ms | 56.6 ms | 30.5% | 1.44× |
| 200,000 | 5.5 MB | 322.0 ms | 225.0 ms | 30.1% | 1.43× |
| 800,000 | 21.9 MB | 1291.9 ms | 895.6 ms | 30.7% | 1.44× |

`json.loads` calls per verification: **4 → 1**, confirmed by instrumenting the module.

**Soundness.** A speedup that changes a verdict is not a speedup. Old and new were run
over all 12 certificate cases in the atlas, anchored and unanchored — 24 verifications
— and the full result was compared, not just the headline: verdict, `ok`, the sorted
error list, and the fingerprint. All 24 identical, including every forgery case.

*A note on the estimate.* This was projected at 27% and first measured at 20%. That
first measurement was wrong in method: it timed the current code against a *simulation*
of the old four-parse shape rather than against the old code, on a run with enough
variance (±25 ms) to swamp the effect. Running the two real versions gives 30%
consistently across three sizes with a spread under 6 ms. The projection was
conservative; the low reading was an artefact of measuring the wrong thing.

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

These per-locus figures pre-date the parse-once change above and are therefore
pessimistic by ~30%; they are left as measured rather than rescaled, because a number
nobody re-ran is not a measurement.

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
