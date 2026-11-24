# gopro

A small Go REST API with JWT auth and user CRUD, backed by PostgreSQL.

Stdlib `net/http` routing, `log/slog`, `pgx`, `golang-jwt`, `bcrypt`. No framework.

## Layout

```
cmd/api/              entrypoint: config, wiring, graceful shutdown
internal/config/      env-based configuration
internal/database/    pgx pool + embedded SQL migrations
internal/user/        domain model, business rules (Service), Postgres store
internal/user/usertest in-memory store for tests
internal/auth/        JWT issue/verify, identity in context
internal/httpapi/     routes, handlers, middleware, JSON helpers
```

Dependencies point inward: `httpapi → auth, user`; `user` knows nothing about HTTP.

## Run

```sh
cp .env.example .env          # set JWT_SECRET
docker compose up --build
```

Or with a local Postgres:

```sh
export $(cat .env | xargs)    # PowerShell: set the vars manually
go run ./cmd/api
```

Migrations in `internal/database/migrations` run automatically on startup.

## Test

```sh
go test ./...
```

## API

| Method | Path                     | Auth          |
|--------|--------------------------|---------------|
| GET    | `/healthz`               | –             |
| GET    | `/readyz`                | – (pings DB)  |
| POST   | `/api/v1/auth/register`  | –             |
| POST   | `/api/v1/auth/login`     | –             |
| GET    | `/api/v1/users/me`       | any user      |
| GET    | `/api/v1/users`          | admin         |
| POST   | `/api/v1/users`          | admin         |
| GET    | `/api/v1/users/{id}`     | self or admin |
| PATCH  | `/api/v1/users/{id}`     | self or admin (role: admin only) |
| DELETE | `/api/v1/users/{id}`     | self or admin |

```sh
curl -X POST localhost:8080/api/v1/auth/register \
  -d '{"name":"Ali","email":"ali@example.com","password":"password123"}'

curl -X POST localhost:8080/api/v1/auth/login \
  -d '{"email":"ali@example.com","password":"password123"}'
# → {"access_token":"...","token_type":"Bearer","expires_at":"..."}

curl localhost:8080/api/v1/users/me -H "Authorization: Bearer <token>"
```

Errors are JSON: `{"error": "...", "fields": {"email": "..."}}`
(400 bad body, 401 auth, 403 forbidden, 404, 409 email taken, 422 validation).
