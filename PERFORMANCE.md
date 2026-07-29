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


## Streaming — and the memory ceiling it does and does not lift

`verify_bundle` parses the whole document, so peak memory runs about **9x the file size**: an
800,000-locus bundle is 22 MB on disk and 210 MB resident. `--stream` walks the document with the
standard library's incremental decoder and verifies one certificate at a time.

Same 22 MB and the same 800,000 loci, differing only in how they are grouped:

| Shape | Ordinary | Streaming | Saving | Ordinary | Streaming |
|---|---|---|---|---|---|
| 100 certificates x 8,000 loci | 214 MB | **69 MB** | 67% | 899 ms | **548 ms** |
| 1 certificate x 800,000 loci | 213 MB | 164 MB | 23% | 895 ms | **549 ms** |
| 200,000 loci | 73 MB | 58 MB | 20% | 224 ms | **137 ms** |

The second row is the honest limit: nothing can stream *inside* one certificate, because its loci
arrays have to exist before they can be checked. If your bundles are one enormous certificate this
buys little, and the fix is to split the certificate — which the format has always allowed.

It is also **faster**, which was not the goal. It never builds the whole document, so it does less
work. An earlier version scanned bytes by hand to find value boundaries; it was correct and four
times *slower*, because a 22 MB byte-at-a-time Python loop costs more than the parse it avoided.
`JSONDecoder.raw_decode` does the same job in C.

`test_streaming_agrees_with_the_ordinary_path` compares the whole result — verdict, errors,
fingerprint, counts — across bundle shapes, forgeries and malformed input.

## Parallel verification — measured, and not built

The plan called for `--jobs` over a process pool, targeting 6x on 8 cores. It was measured first,
and the measurement said no.

Over a 320,000-locus bundle in 64 certificates:

| | |
|---|---|
| serial verify | 371 ms |
| of which parsing | 62 ms (17%) |
| of which certificate checking (the parallel part) | 179 ms (48%) |
| **Amdahl ceiling at 14 cores** | **1.81x** |

And a process pool does not reach the ceiling — it goes backwards, because the certificates have
to be pickled to the workers:

| workers | certificate checking |
|---|---|
| serial | 169 ms |
| 4 | 289 ms (**0.59x**) |
| 8 | 202 ms (0.84x) |
| 14 | 270 ms (0.63x) |

So it is not implemented. Streaming already delivered a 1.6x speedup for free by doing less work
rather than doing it in more places.

## equiv-receipt — watched literals, and the checker that could not read real proofs

Two things were wrong with the DRAT checker, and only one of them was speed.

**It rejected every proof a real solver produces.** Real solvers emit **RAT** lemmas when they
eliminate variables. The checker only knew RUP, so it bailed at the first one. Measured against
CaDiCaL proofs of pigeonhole instances: **5 of 5 rejected**, each within the first few lemmas.
That was not slowness — it was the external-solver path being unusable. RAT checking, plus
deletion lines, fixed it. Those same 5 proofs now verify, and 42 of the 351 lemmas in the
PHP(7,6) proof need the RAT path.

**And it was slow on long proofs.** Naive propagation re-scanned every active clause on every
round, and the active set grows by one per lemma. Two watched literals per clause, an index for
deletion, and truth tracked as a set of true *literals* rather than a variable map:

| Instance | Clauses × lemmas | Before | After | Speedup |
|---|---|---|---|---|
| PHP(5,4) | 45 × 103 | 1.7 ms | 0.8 ms | 2.1× |
| PHP(6,5) | 81 × 749 | 54.9 ms | 11.8 ms | 4.7× |
| PHP(7,6) | 133 × 6,491 | 3,775 ms | 380 ms | **9.9×** |

**This missed its target and the target was right to set.** The goal was ≥20× (under 200 ms on
PHP(7,6)); the result is 9.9× at 380 ms. What remains is Python interpreter cost in the
propagation loop, not an algorithmic defect — profiling shows 89% of the time inside `propagate`
with no single hot call to remove. Getting the rest needs backward (core-first) checking, which is
how DRAT-trim does it and is a much larger change. It is not done, and this table says so.

Those proofs come from the bundled solver, which emits **no deletion lines**, so the clause set
grows monotonically — the pathological case. A real solver's proof of the same instance is 351
lemmas with deletions and checks in **3.9 ms**.

The naive implementation is still there, still the specification, and 25 randomised differential
tests check the fast path against it on every run.

## prereg-seal — dominated by JSON serialisation

| Keys | Digest |
|---|---|
| 10 | 0.1 ms |
| 1,000 | 2.0 ms |
| 20,000 | 45.6 ms |

Acceptance specifications are tens of keys. This is irrelevant at real sizes.

## cert-atlas — scoring is process spawn, so make them overlap

Building the 36-case corpus: **0.05 s**. Scoring it in-process: **6.6 ms**.

Scoring an *external* verifier is a different shape entirely, because every case is a subprocess
and the cost is interpreter startup — **92 ms per case**, 3.3 s for the corpus, and roughly 90 s
for a thousand-case atlas. That is exactly the workload `cert-atlas score` and the submission path
run, so it is the number that matters.

Subprocesses release the GIL while they wait, so a thread pool helps. How much depends on how
contended the machine is, and that turned out to matter more than expected — so both measurements
are here rather than the flattering one.

| `--jobs` | Idle machine | Loaded machine (load avg ≈ 5) |
|---|---|---|
| 1 | 3260 ms — 1.00× | 2944 ms — 1.00× |
| 4 | 805 ms — 4.05× | 833 ms — 3.53× |
| 8 | 519 ms — 6.29× | 739 ms — 3.98× |
| 16 | 484 ms — **6.73×** | 743 ms — **3.96×** |

**Expect about 4×, not 6.7×.** The 6.73× figure was real and is reproducible on an otherwise idle
14-core machine; on the same machine under ordinary load it is 3.7–4.1×, and that is the number a
reader is more likely to see. Returns flatten past `--jobs 8` in both cases.

Results are assembled in index order regardless of scheduling, so the score, the row order and the
missed list are identical at any `--jobs`. A test asserts that, and another asserts that a hostile
verifier — one that calls `sys.exit`, raises, or dies — is still contained per-case rather than
taking down the run.

## What is *not* measured here

Wall-clock of the closed certification engine that *produces* certificates. That is a
different product and a different cost profile; nothing in this repository speaks to it.
