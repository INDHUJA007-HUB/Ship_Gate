# Contributing to First Commit

Thanks for helping make AI-assisted shipping safer.

## Development

Use Python 3.12 or newer, create a virtual environment, and install the dev
extras with `pip install -e ".[dev]"`. Run `pytest` and `ruff check .` before
opening a pull request. CI runs the same checks.

## Change boundaries

- Do not execute scanned repositories in tests, tools, or integration code.
- Add a fixture and a false-positive test for every new detector rule.
- Keep normalized findings backwards-compatible or explicitly bump
  `schema_version`.
- Never add a path that commits, merges, or deploys a user's change directly.
- Record non-trivial architectural decisions in `docs/ADRs/`.

## Security reports

Do not file public issues for vulnerabilities that expose credentials or allow
unsafe scanning behavior. Email the maintainers listed in `SECURITY.md` once it
is configured; until then, open a private GitHub security advisory.

