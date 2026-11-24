package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/yourname/gopro/internal/user"
)

const maxBodyBytes = 1 << 20 // 1 MiB

type errorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // client gone; nothing useful to do
}

func writeMessage(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

// writeError maps domain errors to HTTP responses. Unknown errors are logged
// and reported as 500 without leaking details.
func (s *server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var verr user.ValidationError
	switch {
	case errors.As(err, &verr):
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse{Error: verr.Error(), Fields: verr})
	case errors.Is(err, user.ErrNotFound):
		writeMessage(w, http.StatusNotFound, err.Error())
	case errors.Is(err, user.ErrEmailTaken):
		writeMessage(w, http.StatusConflict, err.Error())
	case errors.Is(err, user.ErrInvalidCredentials):
		writeMessage(w, http.StatusUnauthorized, err.Error())
	default:
		s.logger.ErrorContext(r.Context(), "request failed",
			"method", r.Method,
			"path", r.URL.Path,
			"err", err,
		)
		writeMessage(w, http.StatusInternalServerError, "internal server error")
	}
}

// decodeJSON reads a single JSON object from the body into dst, rejecting
// unknown fields and oversized bodies.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("request body must not exceed %d bytes", maxErr.Limit)
		}
		if errors.Is(err, io.EOF) {
			return errors.New("request body must not be empty")
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}
