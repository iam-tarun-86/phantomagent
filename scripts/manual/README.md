# Manual demo / verification scripts

These are **not** automated tests — they are print-based drivers that require a running
backend, Docker lab, or live LLM endpoint, and they assert nothing. They were previously
named `test_phase*.py` at the repo root, which made pytest try to collect them.

The real test suite lives in `backend/tests/` and runs with:

```bash
backend/venv/bin/python -m pytest
```

Run these manually from the repo root with `PYTHONPATH=.`, e.g.:

```bash
PYTHONPATH=. backend/venv/bin/python scripts/manual/verify_e2e.py
```
