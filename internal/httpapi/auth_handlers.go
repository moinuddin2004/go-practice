package httpapi

import (
	"net/http"
	"time"

	"github.com/yourname/gopro/internal/user"
)

type registerRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, err.Error())
		return
	}

	u, err := s.users.Create(r.Context(), user.CreateParams{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
		Role:     user.RoleUser,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toUserResponse(u))
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, err.Error())
		return
	}

	u, err := s.users.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	token, exp, err := s.tokens.Issue(u.ID, u.Role)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   exp.UTC(),
	})
}
