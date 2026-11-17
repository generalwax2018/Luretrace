# Contributing to luretrace

Thanks for considering a contribution. luretrace is a defensive security tool; contributions are
welcome, with a few expectations particular to this kind of project.

## Scope and intent

luretrace exists to **detect and contain** credential phishing, especially adversary-in-the-middle
kits. Contributions should serve defenders. We will not accept changes whose primary purpose is
offensive — building phishing kits, evading other defenders' tooling, credential harvesting, or
weaponising the deception features against third parties who have not consented.

## Development setup

```bash
git clone <your fork>
cd Luretrace
pip install -e ".[dev,web]"
python -m playwright install chromium   # for the end-to-end detonation tests
pytest
```

All tests should pass. The browser end-to-end tests skip automatically if Chromium is not
installed; please install it and run them before submitting changes to the detonation worker.

## Guidelines

- **Keep the SSRF guard intact.** Any change to the detonation or gate paths must preserve the
  rule that only public addresses are ever fetched. Add a test if you touch this.
- **New detection signals** go in `src/luretrace/signals.py` with a unit test covering a true
  positive and a true negative. Calibrate scores conservatively; false positives on legitimate
  sign-in pages are worse than a missed heuristic here.
- **Mark unvalidated integrations** (anything written to a vendor's API docs but not run against a
  live tenant) as experimental in a docstring, as the existing connectors are.
- **No secrets** in commits. `config.yaml`, `scans/`, and `iocs/` are gitignored; keep it that way.
- Match the existing style: standard library first, small focused modules, type hints, and prose
  docstrings that explain *why*.

## Submitting

1. Branch from `main`.
2. Add or update tests; run `pytest`.
3. Open a PR describing what changed and why, and how you tested it.
4. For anything security-sensitive in luretrace itself, see [`SECURITY.md`](SECURITY.md) first.

By contributing you agree your contributions are licensed under the project's MIT license.
