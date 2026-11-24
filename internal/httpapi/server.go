// Package httpapi exposes the application over HTTP.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/yourname/gopro/internal/auth"
	"github.com/yourname/gopro/internal/user"
)

// Pinger reports whether a dependency (e.g. the database) is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

type server struct {
	users  *user.Service
	tokens *auth.TokenManager
	db     Pinger
	logger *slog.Logger
}

// New returns the root HTTP handler with all routes and middleware wired.
func New(users *user.Service, tokens *auth.TokenManager, db Pinger, logger *slog.Logger) http.Handler {
	s := &server{users: users, tokens: tokens, db: db, logger: logger}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)

	mux.HandleFunc("POST /api/v1/auth/register", s.handleRegister)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)

	mux.Handle("GET /api/v1/users/me", s.authenticate(s.handleMe))
	mux.Handle("GET /api/v1/users", s.authenticate(requireAdmin(s.handleListUsers)))
	mux.Handle("POST /api/v1/users", s.authenticate(requireAdmin(s.handleCreateUser)))
	mux.Handle("GET /api/v1/users/{id}", s.authenticate(s.handleGetUser))
	mux.Handle("PATCH /api/v1/users/{id}", s.authenticate(s.handleUpdateUser))
	mux.Handle("DELETE /api/v1/users/{id}", s.authenticate(s.handleDeleteUser))

	return s.recoverPanic(s.logRequests(mux))
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.Ping(ctx); err != nil {
		s.logger.WarnContext(ctx, "readiness check failed", "err", err)
		writeMessage(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
