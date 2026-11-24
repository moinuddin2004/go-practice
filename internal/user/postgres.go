package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pgUniqueViolation = "23505"

const userColumns = "id, name, email, password_hash, role, created_at, updated_at"

// PostgresStore is a Store backed by PostgreSQL.
type PostgresStore struct {
	db *pgxpool.Pool
}

// NewPostgresStore returns a PostgresStore using db.
func NewPostgresStore(db *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Create(ctx context.Context, u *User) error {
	const q = `
		INSERT INTO users (name, email, password_hash, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`

	err := s.db.QueryRow(ctx, q, u.Name, u.Email, u.PasswordHash, string(u.Role)).
		Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrEmailTaken
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetByID(ctx context.Context, id int64) (*User, error) {
	q := "SELECT " + userColumns + " FROM users WHERE id = $1"
	return s.getOne(ctx, q, id)
}

func (s *PostgresStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	q := "SELECT " + userColumns + " FROM users WHERE email = $1"
	return s.getOne(ctx, q, email)
}

func (s *PostgresStore) List(ctx context.Context, limit, offset int) ([]User, error) {
	q := "SELECT " + userColumns + " FROM users ORDER BY id LIMIT $1 OFFSET $2"

	rows, err := s.db.Query(ctx, q, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := make([]User, 0, limit)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, *u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (s *PostgresStore) Update(ctx context.Context, u *User) error {
	const q = `
		UPDATE users
		SET name = $2, email = $3, password_hash = $4, role = $5, updated_at = now()
		WHERE id = $1
		RETURNING updated_at`

	err := s.db.QueryRow(ctx, q, u.ID, u.Name, u.Email, u.PasswordHash, string(u.Role)).
		Scan(&u.UpdatedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case isUniqueViolation(err):
		return ErrEmailTaken
	case err != nil:
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

func (s *PostgresStore) Delete(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) getOne(ctx context.Context, q string, arg any) (*User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, q, arg))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

func scanUser(row pgx.Row) (*User, error) {
	var (
		u    User
		role string
	)
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &role, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Role = Role(role)
	return &u, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}
