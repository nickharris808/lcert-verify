# Contributing

This package is a **verifier**. Its value comes from being small enough that a
skeptical reader can audit it in an afternoon, so contributions are held to an
unusual constraint:

## The rules

1. **Standard library only, forever.** No dependency may be added to
   `lcert_verify._verifier`. Not numpy, not cryptography, not anything. If a
   change requires a dependency, it belongs in a different package.
2. **The verifier never trusts a recorded value.** If a field can be
   re-derived from more primitive fields, it must be. A patch that reads a
   verdict instead of recomputing it will be declined.
3. **Every new check needs a tamper test.** Show the check failing on a
   deliberately corrupted bundle. A check with no failing case is decoration.
4. **Scope honesty.** If a change alters what is and is not verified, update
   `SCOPE` in the same commit.

## Running the tests

```
pip install -e ".[test]"
pytest
```

The suite must pass, and `test_runs_isolated_with_no_site_packages` must pass in
particular — it is what proves the "no install, no dependencies" claim.

## Reporting a soundness bug

A bundle that verifies but should not is the most serious class of bug here.
Please include the bundle directory and the expected verdict.
