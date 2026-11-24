// Package auth issues and verifies JWT access tokens and carries the
// authenticated identity through request contexts.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yourname/gopro/internal/user"
)

const issuer = "gopro"

// ErrInvalidToken is returned for any token that fails verification.
var ErrInvalidToken = errors.New("invalid token")

// Identity is the authenticated caller.
type Identity struct {
	UserID int64
	Role   user.Role
}

// IsAdmin reports whether the caller has the admin role.
func (id Identity) IsAdmin() bool {
	return id.Role == user.RoleAdmin
}

type claims struct {
	Role user.Role `json:"role"`
	jwt.RegisteredClaims
}

// TokenManager signs and parses HS256 access tokens.
type TokenManager struct {
	secret []byte
	ttl    time.Duration
}

// NewTokenManager returns a TokenManager that signs with secret and issues
// tokens valid for ttl.
func NewTokenManager(secret string, ttl time.Duration) *TokenManager {
	return &TokenManager{secret: []byte(secret), ttl: ttl}
}

// Issue creates a signed token for the given user and returns it with its expiry.
func (m *TokenManager) Issue(userID int64, role user.Role) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(m.ttl)

	c := claims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(userID, 10),
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}
	return token, exp, nil
}

// Parse verifies token and returns the identity it carries.
func (m *TokenManager) Parse(token string) (Identity, error) {
	var c claims
	_, err := jwt.ParseWithClaims(token, &c,
		func(*jwt.Token) (any, error) { return m.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	id, err := strconv.ParseInt(c.Subject, 10, 64)
	if err != nil || !c.Role.Valid() {
		return Identity{}, ErrInvalidToken
	}
	return Identity{UserID: id, Role: c.Role}, nil
}

type ctxKey struct{}

// NewContext returns a copy of ctx carrying id.
func NewContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identity stored in ctx, if any.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}
