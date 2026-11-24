package httpapi

import (
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/yourname/gopro/internal/auth"
)

// authenticate rejects requests without a valid bearer token and stores the
// caller's identity in the request context.
func (s *server) authenticate(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeMessage(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		id, err := s.tokens.Parse(token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeMessage(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		next(w, r.WithContext(auth.NewContext(r.Context(), id)))
	})
}

// requireAdmin must be wrapped by authenticate.
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if id, _ := auth.FromContext(r.Context()); !id.IsAdmin() {
			writeMessage(w, http.StatusForbidden, "admin access required")
			return
		}
		next(w, r)
	}
}

func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		s.logger.InfoContext(r.Context(), "http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start),
			"remote", r.RemoteAddr,
		)
	})
}

func (s *server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			s.logger.ErrorContext(r.Context(), "panic recovered",
				"panic", v,
				"stack", string(debug.Stack()),
			)
			w.Header().Set("Connection", "close")
			writeMessage(w, http.StatusInternalServerError, "internal server error")
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
