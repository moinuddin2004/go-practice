// Package usertest provides an in-memory user.Store for tests.
package usertest

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/yourname/gopro/internal/user"
)

// Store is a concurrency-safe, in-memory user.Store.
type Store struct {
	mu     sync.Mutex
	nextID int64
	users  map[int64]user.User
}

var _ user.Store = (*Store)(nil)

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{users: make(map[int64]user.User)}
}

func (s *Store) Create(_ context.Context, u *user.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.emailTaken(u.Email, 0) {
		return user.ErrEmailTaken
	}
	s.nextID++
	now := time.Now().UTC()
	u.ID, u.CreatedAt, u.UpdatedAt = s.nextID, now, now
	s.users[u.ID] = *u
	return nil
}

func (s *Store) GetByID(_ context.Context, id int64) (*user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		return nil, user.ErrNotFound
	}
	return &u, nil
}

func (s *Store) GetByEmail(_ context.Context, email string) (*user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.Email == email {
			return &u, nil
		}
	}
	return nil, user.ErrNotFound
}

func (s *Store) List(_ context.Context, limit, offset int) ([]user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all := slices.SortedFunc(maps.Values(s.users), func(a, b user.User) int {
		return cmp.Compare(a.ID, b.ID)
	})
	if offset >= len(all) {
		return []user.User{}, nil
	}
	return all[offset:min(offset+limit, len(all))], nil
}

func (s *Store) Update(_ context.Context, u *user.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[u.ID]; !ok {
		return user.ErrNotFound
	}
	if s.emailTaken(u.Email, u.ID) {
		return user.ErrEmailTaken
	}
	u.UpdatedAt = time.Now().UTC()
	s.users[u.ID] = *u
	return nil
}

func (s *Store) Delete(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[id]; !ok {
		return user.ErrNotFound
	}
	delete(s.users, id)
	return nil
}

// emailTaken must be called with mu held.
func (s *Store) emailTaken(email string, exceptID int64) bool {
	for id, u := range s.users {
		if u.Email == email && id != exceptID {
			return true
		}
	}
	return false
}
