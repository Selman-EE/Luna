# Luna Gateway

API Gateway built with **.NET 8** and **YARP**.

## Responsibilities
- Validate **external (user) JWT**
- Apply authorization using internal role/permission logic
- Mint **short-lived internal JWTs** for downstream services
- Replace `Authorization` header before proxying
- Expose **JWKS** for internal JWT validation

## Architecture
Client
→ Gateway
→ Internal JWT (aud + scopes, short TTL)
→ Microservice (local JWT validation)


## Endpoints
- `GET /health`  
  Health check

- `GET /.well-known/internal-jwks.json`  
  Public keys used by internal services to validate tokens

- Proxied routes (examples):
  - `/bets/*` → BetsService
  - `/odds/*` → OddsService

## Internal JWT Claims
- `iss` – `company-gateway`
- `aud` – target service (e.g. `bets-service`)
- `scp` – scopes (e.g. `bets.read`)
- `sub` – user identifier
- `act` – calling service (`api-gateway`)
- `exp` – short expiration (default: 120 seconds)

## Configuration
- `ExternalAuth`  
  User JWT validation (replace with your real auth system)

- `InternalTokens`  
  Signing keys + TTL for internal JWTs

- `ReverseProxy`  
  YARP routes with metadata:
  - `InternalAudience`
  - `InternalScopes`

## Security Model
- User JWT **never reaches** downstream services
- All internal traffic requires a valid internal JWT
- Services validate tokens **locally via JWKS**
- No runtime dependency on the gateway for validation

## Run
```bash
dotnet run --project src/Gateway
