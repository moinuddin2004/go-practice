// Package config loads application configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Config holds all runtime configuration for the API.
type Config struct {
	HTTPAddr        string
	DatabaseURL     string
	JWTSecret       string
	JWTTTL          time.Duration
	ShutdownTimeout time.Duration
	LogLevel        string

	// Optional: when both are set, an admin account is created on startup
	// if it does not already exist.
	AdminEmail    string
	AdminPassword string
}

// Load reads configuration from the environment and validates it.
func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:      getEnv("HTTP_ADDR", ":8080"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		JWTSecret:     os.Getenv("JWT_SECRET"),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		AdminEmail:    os.Getenv("ADMIN_EMAIL"),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
	}

	var err error
	if cfg.JWTTTL, err = getDuration("JWT_TTL", time.Hour); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = getDuration("SHUTDOWN_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if len(c.JWTSecret) < 32 {
		errs = append(errs, errors.New("JWT_SECRET must be at least 32 characters"))
	}
	if c.JWTTTL <= 0 {
		errs = append(errs, errors.New("JWT_TTL must be positive"))
	}
	if (c.AdminEmail == "") != (c.AdminPassword == "") {
		errs = append(errs, errors.New("ADMIN_EMAIL and ADMIN_PASSWORD must be set together"))
	}
	return errors.Join(errs...)
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid duration %q: %w", key, v, err)
	}
	return d, nil
}
