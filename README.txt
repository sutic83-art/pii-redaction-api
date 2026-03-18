v2 upgrade:
- strict validation for JMBG and PIB
- invalid numbers are ignored instead of redacted
- JSON audit logging
- .dockerignore included

Run:
docker compose build --no-cache
docker compose run --rm api python -m pytest -q
docker compose up --build
