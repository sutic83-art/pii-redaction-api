# PII Redaction API

FastAPI servis za redakciju osetljivih identifikatora, sa fokusom na srpske formate kao što su JMBG i PIB.

## Funkcionalnosti

- validacija JMBG
- validacija PIB
- politike redakcije:
  - `mask`
  - `hash`
  - `rm`
- audit log bez čuvanja sirovog teksta
- rate limiting
- Docker podrška
- GitHub Actions CI
- Render deploy

## Endpointi

- `GET /`
- `GET /health`
- `GET /docs`
- `POST /redact`
- `POST /api/v1/redact`

## Primer request body

```json
{
  "text": "JMBG 0101990712345 i PIB 100000049",
  "policy": "mask"
}