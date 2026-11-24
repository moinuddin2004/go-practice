// Package user contains the user domain: model, business rules and storage.
package user

import (
	"errors"
	"time"
)

// Role is a user's authorization role.
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	return r == RoleUser || r == RoleAdmin
}

// User is a registered account.
type User struct {
	ID           int64
	Name         string
	Email        string
	PasswordHash string
	Role         Role
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

var (
	ErrNotFound           = errors.New("user not found")
	ErrEmailTaken         = errors.New("email already in use")
	ErrInvalidCredentials = errors.New("invalid email or password")
)

// ValidationError maps field names to human-readable problems.
type ValidationError map[string]string

func (v ValidationError) Error() string {
	return "validation failed"
}
