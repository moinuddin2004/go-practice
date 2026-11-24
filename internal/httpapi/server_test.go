package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yourname/gopro/internal/auth"
	"github.com/yourname/gopro/internal/httpapi"
	"github.com/yourname/gopro/internal/user"
	"github.com/yourname/gopro/internal/user/usertest"
)

type okPinger struct{}

func (okPinger) Ping(context.Context) error { return nil }

type testAPI struct {
	t     *testing.T
	srv   *httptest.Server
	users *user.Service
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	users := user.NewService(usertest.NewStore())
	tokens := auth.NewTokenManager(strings.Repeat("s", 32), time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := httptest.NewServer(httpapi.New(users, tokens, okPinger{}, logger))
	t.Cleanup(srv.Close)
	return &testAPI{t: t, srv: srv, users: users}
}

// do sends a JSON request and decodes the JSON response (if any) into a map.
func (a *testAPI) do(method, path, token string, body any) (int, map[string]any) {
	a.t.Helper()

	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			a.t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, a.srv.URL+path, &buf)
	if err != nil {
		a.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := a.srv.Client().Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()

	var out map[string]any
	if resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			a.t.Fatalf("%s %s: decode response: %v", method, path, err)
		}
	}
	return resp.StatusCode, out
}

func (a *testAPI) register(name, email, password string) int64 {
	a.t.Helper()
	status, body := a.do("POST", "/api/v1/auth/register", "", map[string]string{
		"name": name, "email": email, "password": password,
	})
	if status != http.StatusCreated {
		a.t.Fatalf("register %s: status %d, body %v", email, status, body)
	}
	return int64(body["id"].(float64))
}

func (a *testAPI) login(email, password string) string {
	a.t.Helper()
	status, body := a.do("POST", "/api/v1/auth/login", "", map[string]string{
		"email": email, "password": password,
	})
	if status != http.StatusOK {
		a.t.Fatalf("login %s: status %d, body %v", email, status, body)
	}
	return body["access_token"].(string)
}

func TestAuthFlow(t *testing.T) {
	api := newTestAPI(t)

	api.register("Ali", "ali@example.com", "password123")

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
	}{
		{"duplicate email", "POST", "/api/v1/auth/register",
			map[string]string{"name": "Ali", "email": "ALI@example.com", "password": "password123"}, http.StatusConflict},
		{"short password", "POST", "/api/v1/auth/register",
			map[string]string{"name": "Bob", "email": "bob@example.com", "password": "short"}, http.StatusUnprocessableEntity},
		{"unknown field", "POST", "/api/v1/auth/register",
			map[string]string{"name": "Bob", "email": "bob@example.com", "password": "password123", "role": "admin"}, http.StatusBadRequest},
		{"wrong password", "POST", "/api/v1/auth/login",
			map[string]string{"email": "ali@example.com", "password": "wrong-password"}, http.StatusUnauthorized},
		{"unknown email", "POST", "/api/v1/auth/login",
			map[string]string{"email": "nobody@example.com", "password": "password123"}, http.StatusUnauthorized},
		{"me without token", "GET", "/api/v1/users/me", nil, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if status, body := api.do(tt.method, tt.path, "", tt.body); status != tt.want {
				t.Errorf("status = %d, want %d (body %v)", status, tt.want, body)
			}
		})
	}

	t.Run("me with token", func(t *testing.T) {
		token := api.login("ali@example.com", "password123")
		status, body := api.do("GET", "/api/v1/users/me", token, nil)
		if status != http.StatusOK || body["email"] != "ali@example.com" || body["role"] != "user" {
			t.Errorf("got status %d, body %v", status, body)
		}
		if _, leaked := body["password_hash"]; leaked {
			t.Error("password hash leaked in response")
		}
	})

	t.Run("tampered token", func(t *testing.T) {
		token := api.login("ali@example.com", "password123") + "x"
		if status, _ := api.do("GET", "/api/v1/users/me", token, nil); status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})
}

func TestUserAccessControl(t *testing.T) {
	api := newTestAPI(t)

	if err := api.users.EnsureAdmin(context.Background(), "admin@example.com", "admin-password"); err != nil {
		t.Fatal(err)
	}
	aliID := api.register("Ali", "ali@example.com", "password123")
	bobID := api.register("Bob", "bob@example.com", "password123")

	ali := api.login("ali@example.com", "password123")
	admin := api.login("admin@example.com", "admin-password")

	bobPath := fmt.Sprintf("/api/v1/users/%d", bobID)
	aliPath := fmt.Sprintf("/api/v1/users/%d", aliID)

	steps := []struct {
		name   string
		method string
		path   string
		token  string
		body   any
		want   int
	}{
		{"user cannot list users", "GET", "/api/v1/users", ali, nil, http.StatusForbidden},
		{"user cannot read another user", "GET", bobPath, ali, nil, http.StatusForbidden},
		{"user cannot delete another user", "DELETE", bobPath, ali, nil, http.StatusForbidden},
		{"user cannot change own role", "PATCH", aliPath, ali, map[string]string{"role": "admin"}, http.StatusForbidden},
		{"user updates own name", "PATCH", aliPath, ali, map[string]string{"name": "Ali Khan"}, http.StatusOK},
		{"invalid id", "GET", "/api/v1/users/abc", ali, nil, http.StatusBadRequest},
		{"admin lists users", "GET", "/api/v1/users?limit=10", admin, nil, http.StatusOK},
		{"admin creates user", "POST", "/api/v1/users", admin,
			map[string]string{"name": "Sara", "email": "sara@example.com", "password": "password123", "role": "admin"}, http.StatusCreated},
		{"admin rejects bad role", "POST", "/api/v1/users", admin,
			map[string]string{"name": "X", "email": "x@example.com", "password": "password123", "role": "root"}, http.StatusUnprocessableEntity},
		{"admin deletes user", "DELETE", bobPath, admin, nil, http.StatusNoContent},
		{"deleted user is gone", "GET", bobPath, admin, nil, http.StatusNotFound},
	}
	for _, s := range steps {
		if status, body := api.do(s.method, s.path, s.token, s.body); status != s.want {
			t.Fatalf("%s: status = %d, want %d (body %v)", s.name, status, s.want, body)
		}
	}

	if _, body := api.do("GET", aliPath, ali, nil); body["name"] != "Ali Khan" {
		t.Errorf("name = %v, want %q", body["name"], "Ali Khan")
	}
}
