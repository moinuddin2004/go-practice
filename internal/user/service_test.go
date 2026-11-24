package user_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yourname/gopro/internal/user"
	"github.com/yourname/gopro/internal/user/usertest"
)

func TestCreateValidation(t *testing.T) {
	svc := user.NewService(usertest.NewStore())

	tests := []struct {
		name      string
		params    user.CreateParams
		wantField string
	}{
		{"empty name", user.CreateParams{Email: "a@b.com", Password: "password123"}, "name"},
		{"bad email", user.CreateParams{Name: "A", Email: "not-an-email", Password: "password123"}, "email"},
		{"display-name email", user.CreateParams{Name: "A", Email: "A <a@b.com>", Password: "password123"}, "email"},
		{"short password", user.CreateParams{Name: "A", Email: "a@b.com", Password: "123"}, "password"},
		{"unknown role", user.CreateParams{Name: "A", Email: "a@b.com", Password: "password123", Role: "root"}, "role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Create(context.Background(), tt.params)

			var verr user.ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("err = %v, want ValidationError", err)
			}
			if _, ok := verr[tt.wantField]; !ok {
				t.Errorf("fields = %v, want error on %q", verr, tt.wantField)
			}
		})
	}
}

func TestCreateNormalizesAndHashes(t *testing.T) {
	svc := user.NewService(usertest.NewStore())

	u, err := svc.Create(context.Background(), user.CreateParams{
		Name: "  Ali  ", Email: " Ali@Example.COM ", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "Ali" || u.Email != "ali@example.com" || u.Role != user.RoleUser {
		t.Errorf("got %+v", u)
	}
	if u.PasswordHash == "" || u.PasswordHash == "password123" {
		t.Error("password was not hashed")
	}
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	svc := user.NewService(usertest.NewStore())
	if _, err := svc.Create(ctx, user.CreateParams{Name: "Ali", Email: "ali@example.com", Password: "password123"}); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Authenticate(ctx, "ALI@example.com", "password123"); err != nil {
		t.Errorf("valid credentials: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "ali@example.com", "wrong"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v", err)
	}
	if _, err := svc.Authenticate(ctx, "nobody@example.com", "password123"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Errorf("unknown email: err = %v", err)
	}
}

func TestUpdatePassword(t *testing.T) {
	ctx := context.Background()
	svc := user.NewService(usertest.NewStore())
	u, err := svc.Create(ctx, user.CreateParams{Name: "Ali", Email: "ali@example.com", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}

	newPass := "new-password-456"
	if _, err := svc.Update(ctx, u.ID, user.UpdateParams{Password: &newPass}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, "ali@example.com", newPass); err != nil {
		t.Errorf("login with new password: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "ali@example.com", "password123"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Errorf("old password still works: err = %v", err)
	}
}
