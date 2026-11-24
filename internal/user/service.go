package user

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	maxNameLen       = 100
	maxEmailLen      = 254
	minPasswordLen   = 8
	maxPasswordLen   = 72 // bcrypt ignores bytes beyond 72
	defaultListLimit = 20
	maxListLimit     = 100
)

// Store is the persistence contract the Service depends on.
type Store interface {
	Create(ctx context.Context, u *User) error
	GetByID(ctx context.Context, id int64) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	List(ctx context.Context, limit, offset int) ([]User, error)
	Update(ctx context.Context, u *User) error
	Delete(ctx context.Context, id int64) error
}

// Service implements user business logic.
type Service struct {
	store Store
}

// NewService returns a Service backed by store.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// CreateParams are the inputs for creating a user.
type CreateParams struct {
	Name     string
	Email    string
	Password string
	Role     Role // defaults to RoleUser
}

// UpdateParams holds optional fields; nil means "leave unchanged".
type UpdateParams struct {
	Name     *string
	Email    *string
	Password *string
	Role     *Role
}

// Create validates p, hashes the password and stores a new user.
func (s *Service) Create(ctx context.Context, p CreateParams) (*User, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.Email = normalizeEmail(p.Email)
	if p.Role == "" {
		p.Role = RoleUser
	}

	v := ValidationError{}
	validateName(v, p.Name)
	validateEmail(v, p.Email)
	validatePassword(v, p.Password)
	validateRole(v, p.Role)
	if len(v) > 0 {
		return nil, v
	}

	hash, err := hashPassword(p.Password)
	if err != nil {
		return nil, err
	}

	u := &User{
		Name:         p.Name,
		Email:        p.Email,
		PasswordHash: hash,
		Role:         p.Role,
	}
	if err := s.store.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// Get returns the user with the given id.
func (s *Service) Get(ctx context.Context, id int64) (*User, error) {
	return s.store.GetByID(ctx, id)
}

// List returns a page of users ordered by id. limit is clamped to [1, 100].
func (s *Service) List(ctx context.Context, limit, offset int) ([]User, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}
	limit = min(limit, maxListLimit)
	offset = max(offset, 0)
	return s.store.List(ctx, limit, offset)
}

// Update applies the non-nil fields of p to the user with the given id.
func (s *Service) Update(ctx context.Context, id int64, p UpdateParams) (*User, error) {
	u, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	v := ValidationError{}
	if p.Name != nil {
		u.Name = strings.TrimSpace(*p.Name)
		validateName(v, u.Name)
	}
	if p.Email != nil {
		u.Email = normalizeEmail(*p.Email)
		validateEmail(v, u.Email)
	}
	if p.Password != nil {
		validatePassword(v, *p.Password)
	}
	if p.Role != nil {
		u.Role = *p.Role
		validateRole(v, u.Role)
	}
	if len(v) > 0 {
		return nil, v
	}

	if p.Password != nil {
		if u.PasswordHash, err = hashPassword(*p.Password); err != nil {
			return nil, err
		}
	}

	if err := s.store.Update(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// Delete removes the user with the given id.
func (s *Service) Delete(ctx context.Context, id int64) error {
	return s.store.Delete(ctx, id)
}

// Authenticate returns the user matching the email and password,
// or ErrInvalidCredentials.
func (s *Service) Authenticate(ctx context.Context, email, password string) (*User, error) {
	u, err := s.store.GetByEmail(ctx, normalizeEmail(email))
	if errors.Is(err, ErrNotFound) {
		// Burn the same CPU time as a real check so response timing
		// doesn't reveal whether the email is registered.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

// EnsureAdmin creates an admin account with the given credentials if no user
// with that email exists yet. An existing account is left untouched.
func (s *Service) EnsureAdmin(ctx context.Context, email, password string) error {
	_, err := s.store.GetByEmail(ctx, normalizeEmail(email))
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}

	_, err = s.Create(ctx, CreateParams{
		Name:     "Admin",
		Email:    email,
		Password: password,
		Role:     RoleAdmin,
	})
	if errors.Is(err, ErrEmailTaken) { // created concurrently by another instance
		return nil
	}
	return err
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateName(v ValidationError, name string) {
	switch {
	case name == "":
		v["name"] = "is required"
	case utf8.RuneCountInString(name) > maxNameLen:
		v["name"] = fmt.Sprintf("must be at most %d characters", maxNameLen)
	}
}

func validateEmail(v ValidationError, email string) {
	switch {
	case email == "":
		v["email"] = "is required"
	case len(email) > maxEmailLen:
		v["email"] = fmt.Sprintf("must be at most %d characters", maxEmailLen)
	default:
		// Reject display-name forms like "Bob <bob@x.com>".
		if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email {
			v["email"] = "must be a valid email address"
		}
	}
}

func validatePassword(v ValidationError, password string) {
	if len(password) < minPasswordLen || len(password) > maxPasswordLen {
		v["password"] = fmt.Sprintf("must be between %d and %d bytes", minPasswordLen, maxPasswordLen)
	}
}

func validateRole(v ValidationError, r Role) {
	if !r.Valid() {
		v["role"] = fmt.Sprintf("must be %q or %q", RoleUser, RoleAdmin)
	}
}
