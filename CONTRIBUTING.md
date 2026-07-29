# Contributing to lcert-verify

This package is part of [certified-oss][p]. **The portfolio-wide guide is
[CONTRIBUTING.md][c] and it is the one to read** — it covers the rules that are not negotiable,
how to install packages that depend on each other, and what kind of contribution is most wanted
(a forgery this project fails to catch).

What is specific to this package:

- **`src/lcert_verify/_verifier.py` is frozen.** It is one stdlib file, small enough to read in
  full, and CI runs it under `python -I -S` with no site-packages. New capability goes in a new
  module that calls into it — `stream.py`, `diff.py`, `html.py`, `serve.py` all do. A third-party
  import is a test failure, checked against `sys.stdlib_module_names`.
- **`CLI.md` is partly generated.** Run `python gen_cli_docs.py` after changing an argument; the
  prose around the markers is hand-written and yours to edit.
- **Judging is never reimplemented.** Streaming, HTTP and the JS port all call the same
  `verify_*_certs` functions. What may differ is how a certificate is reached, never how it is
  judged.

## Working on it

```bash
pip install -e ".[test]"
pytest -q
ruff check .
```

## Licence

Apache-2.0. By contributing you agree your contribution is licensed the same way.

[p]: https://github.com/nickharris808/certified-oss
[c]: https://github.com/nickharris808/certified-oss/blob/main/CONTRIBUTING.md
