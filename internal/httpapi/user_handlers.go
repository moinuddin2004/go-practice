package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/yourname/gopro/internal/auth"
	"github.com/yourname/gopro/internal/user"
)

type userResponse struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Role      user.Role `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toUserResponse(u *user.User) userResponse {
	return userResponse{
		ID:        u.ID,
		Name:      u.Name,
		Email:     u.Email,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

type listUsersResponse struct {
	Users []userResponse `json:"users"`
}

type createUserRequest struct {
	Name     string    `json:"name"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Role     user.Role `json:"role"`
}

type updateUserRequest struct {
	Name     *string    `json:"name"`
	Email    *string    `json:"email"`
	Password *string    `json:"password"`
	Role     *user.Role `json:"role"`
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())

	u, err := s.users.Get(r.Context(), id.UserID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(u))
}

func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	limit, err := queryInt(r, "limit", 0) // service applies default and max
	if err != nil {
		writeMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0)
	if err != nil {
		writeMessage(w, http.StatusBadRequest, err.Error())
		return
	}

	users, err := s.users.List(r.Context(), limit, offset)
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	resp := listUsersResponse{Users: make([]userResponse, 0, len(users))}
	for i := range users {
		resp.Users = append(resp.Users, toUserResponse(&users[i]))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, err.Error())
		return
	}

	u, err := s.users.Create(r.Context(), user.CreateParams{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
		Role:     req.Role,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toUserResponse(u))
}

func (s *server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.authorizeUserAccess(w, r)
	if !ok {
		return
	}

	u, err := s.users.Get(r.Context(), userID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(u))
}

func (s *server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.authorizeUserAccess(w, r)
	if !ok {
		return
	}

	var req updateUserRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	if id, _ := auth.FromContext(r.Context()); req.Role != nil && !id.IsAdmin() {
		writeMessage(w, http.StatusForbidden, "only admins can change roles")
		return
	}

	u, err := s.users.Update(r.Context(), userID, user.UpdateParams{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
		Role:     req.Role,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(u))
}

func (s *server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.authorizeUserAccess(w, r)
	if !ok {
		return
	}

	if err := s.users.Delete(r.Context(), userID); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorizeUserAccess parses the {id} path value and checks that the caller
// is that user or an admin. On failure it writes the response and returns false.
func (s *server) authorizeUserAccess(w http.ResponseWriter, r *http.Request) (int64, bool) {
	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || userID <= 0 {
		writeMessage(w, http.StatusBadRequest, "invalid user id")
		return 0, false
	}

	id, _ := auth.FromContext(r.Context())
	if id.UserID != userID && !id.IsAdmin() {
		writeMessage(w, http.StatusForbidden, "you can only access your own account")
		return 0, false
	}
	return userID, true
}

func queryInt(r *http.Request, key string, fallback int) (int, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("query parameter %q must be a non-negative integer", key)
	}
	return n, nil
}
