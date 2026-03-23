# Python Dependency Audit

## Detect

- `requirements.txt`
- `requirements-dev.txt`
- `constraints.txt`
- `pyproject.toml`
- `poetry.lock`
- `Pipfile.lock`

## Preferred Audit Paths

```bash
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt
python -m pip_audit -r requirements.txt
```

If the repo uses Poetry or Pipenv, prefer the repo's existing export or audit workflow. If that does not exist, audit the lock file manually and record the limitation.

## What To Check

- direct vs transitive vulnerable packages
- unpinned or loosely pinned requirements that make installs drift
- extras and optional dependencies that still land in production images
- framework and runtime EOL
- image, archive, XML, YAML, markdown, auth, and serializer libraries
- local editable installs or copied vendored packages

## Common High-Risk Cases

- old Django, Flask, FastAPI, Starlette, Jinja2, Werkzeug
- parser libraries for image, archive, XML, YAML, PDF, and markdown content
- auth and JWT libraries with weak defaults
- dependencies only declared in `pyproject.toml` while runtime images install from a different file

## Reporting Notes

- Record which requirements or lock file ties the package to the repo.
- Mention if production uses a different dependency source than the scanned file.
- If only base-image packages expose the vulnerable component, keep that under dependency or infra context explicitly.
