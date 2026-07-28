# Troubleshooting

Every entry below is an error you can actually hit, with the cause and the fix.

## `VERDICT: UNVERIFIED` and exit code 4

**Cause.** No trust anchor. You ran `lcert-verify bundle/` without the expected
fingerprint.

**Why it is not a pass or a fail.** Internal consistency cannot distinguish a genuine
certificate from one whose inputs *and* verdict were edited together. The tool refuses
to guess.

**Fix.** Supply the fingerprint you obtained out of band:

```
lcert-verify bundle/ 3f2a...c91
```

If you genuinely only want the weaker check — say, a smoke test on a bundle you produced
yourself seconds ago — opt out explicitly:

```
lcert-verify bundle/ --no-anchor      # verdict becomes INTERNALLY-CONSISTENT
```

## `VERDICT: VERIFIED-VACUOUS`

**Cause.** Every check passed, but no locus carried a proof obligation (`gated loci: 0`).

**Why it is not `VERIFIED`.** Nothing had to be earned, so nothing is claimed. Reporting
success here would sell a guarantee that was never tested.

**Fix.** If you expected gated loci, your locus-selection step produced none — check the
criterion that populates `loci`.

## `VERDICT: VACUOUS` and exit code 3

**Cause.** The bundle contains no certificates at all.

**Fix.** If deliberate, pass `--allow-empty`. If not, the producing step emitted nothing;
check its output before packaging.

## `bundle fingerprint != expected` and exit code 2

**Cause.** The bundle's bytes differ from the anchor you supplied.

**Fix.** Confirm you are comparing against the right artifact. Note that *any* byte
difference triggers this, including a re-serialisation that changes nothing semantically —
that is deliberate, since the anchor's whole job is byte-level.

## `bundle.json is not canonical JSON (round-trip differs)`

**Cause.** The file was rewritten by a tool that reformatted it — `json.dumps` with
indentation, an editor that added a trailing newline, a pretty-printer.

**Fix.** Canonical form is `sort_keys=True, separators=(",", ":")`. Use
`lcert_verify._verifier._canon` to rewrite it, or do not modify it at all.

## `non-finite value(s) in ...`

**Cause.** A `NaN` or `Infinity` reached the certificate. These are **not valid JSON**;
a document containing them is rejected by strict parsers, including every browser.

**Fix.** Find the upstream computation producing a non-finite intensity. This is always a
bug in the producer, never a formatting choice.

## `recorded <field>=X but re-derived Y`

**Cause.** The recorded verdict disagrees with what the shipped numbers imply. Either the
certificate was tampered with, or the producer and this verifier disagree.

**Fix.** If you produced it, your gate and this verifier have diverged — that is a real
inconsistency worth chasing, not a formatting issue. If you received it, treat the
certificate as refuted.

## `bundle.json must be a JSON object, got list`

**Cause.** Valid JSON of the wrong shape.

**Fix.** A bundle is an object. You have probably pointed at the wrong file.

## `pip install` cannot find `lcert-verify>=1.0.0`

**Cause.** Nothing is published to PyPI yet.

**Fix.** Install from the repository:

```
pip install git+https://github.com/nickharris808/lcert-verify.git
```

For local development of several packages at once, see CONTRIBUTING.

## Something else

The verifier's full scope statement — what it checks and what it deliberately does not —
is one command away:

```
lcert-verify --scope
```
