package config

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/skxm03/kr0n-backend/control-plane/internal/auth/jwtkeys"
)

var (
	// ErrMissingDatabaseURL indicates the DATABASE_URL environment variable is not set.
	ErrMissingDatabaseURL = errors.New("missing required environment variable: DATABASE_URL")

	// ErrEmptyDatabaseURL indicates the DATABASE_URL environment variable is empty.
	ErrEmptyDatabaseURL = errors.New("DATABASE_URL cannot be empty")

	// ErrInvalidDatabaseURL indicates the DATABASE_URL environment variable is malformed.
	ErrInvalidDatabaseURL = errors.New("DATABASE_URL is invalid")
)

// Config represents the application configuration for database-backed services.
type Config struct {
	DatabaseURL                    string
	AuthGRPCAddr                   string
	Env                            string
	JWTPrivateKey                  ed25519.PrivateKey
	JWTKeyID                       string
	JWTIssuer                      string
	JWTAudience                    string
	AccessTokenLifetime            time.Duration
	RefreshTokenLifetime           time.Duration
	EmailVerificationTokenLifetime time.Duration
	PasswordResetTokenLifetime     time.Duration
	RequireVerifiedEmail           bool
	SMTPAddr                       string
	SMTPFrom                       string
	SMTPUsername                   string
	SMTPPassword                   string
	GitHubClientID                 string
	GitHubClientSecret             string
	GitHubRedirectURL              string
	AuthGRPCTLSCertFile            string
	AuthGRPCTLSKeyFile             string
	AuthGRPCClientCAFile           string
	AuthGRPCAllowedClients         []string
	AuthServiceToken               string
}

// IsDevEnv reports whether the environment name represents a local development environment.
func IsDevEnv(env string) bool {
	return strings.EqualFold(env, "dev") || strings.EqualFold(env, "development")
}

// GatewayConfig represents configuration for the API Gateway service.
type GatewayConfig struct {
	GatewayHTTPAddr string
	AuthGRPCAddr    string
	Env             string

	JWTPublicKeys map[string]ed25519.PublicKey
	JWTIssuer     string
	JWTAudience   string

	RedisAddr      string
	TrustedProxies []*net.IPNet

	// Leaky-bucket policies: capacity is the burst, rate is the sustained requests/second.
	GeneralRateCapacity int
	GeneralRatePerSec   float64
	AuthRateCapacity    int
	AuthRatePerSec      float64

	AuthGRPCTLSCAFile   string
	AuthGRPCTLSCertFile string
	AuthGRPCTLSKeyFile  string
	AuthGRPCTLSPlain    bool
	AuthServiceToken    string
}

// Load loads and validates configuration from the process environment.
func Load() (*Config, error) {
	return LoadFrom(os.LookupEnv)
}

// LoadFrom loads and validates configuration using the provided environment lookup function.
func LoadFrom(lookup func(string) (string, bool)) (*Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	rawURL, ok := lookup("DATABASE_URL")
	if !ok {
		return nil, ErrMissingDatabaseURL
	}

	databaseURL := strings.TrimSpace(rawURL)
	if databaseURL == "" {
		return nil, ErrEmptyDatabaseURL
	}

	u, err := url.Parse(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDatabaseURL, err)
	}

	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("%w: scheme must be postgres:// or postgresql://", ErrInvalidDatabaseURL)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrInvalidDatabaseURL)
	}

	authGRPCAddr := ":50051"
	if raw, ok := lookup("AUTH_GRPC_ADDR"); ok && strings.TrimSpace(raw) != "" {
		authGRPCAddr = strings.TrimSpace(raw)
	}

	env := envOr(lookup, "KR0N_ENV", "dev")

	var jwtPrivateKey ed25519.PrivateKey
	if raw, ok := lookup("JWT_PRIVATE_KEY"); ok && strings.TrimSpace(raw) != "" {
		k, err := jwtkeys.ParsePrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT_PRIVATE_KEY: %w", err)
		}
		if env != "dev" && bytes.Equal(k, jwtkeys.DevPrivateKey()) {
			return nil, errors.New("default dev JWT_PRIVATE_KEY is forbidden when KR0N_ENV != dev")
		}
		jwtPrivateKey = k
	} else if env != "dev" {
		return nil, errors.New("JWT_PRIVATE_KEY is required when KR0N_ENV != dev")
	} else {
		jwtPrivateKey = jwtkeys.DevPrivateKey()
	}

	tlsCert := envOr(lookup, "AUTH_GRPC_TLS_CERT_FILE", "")
	tlsKey := envOr(lookup, "AUTH_GRPC_TLS_KEY_FILE", "")
	if (tlsCert == "") != (tlsKey == "") {
		return nil, errors.New("both AUTH_GRPC_TLS_CERT_FILE and AUTH_GRPC_TLS_KEY_FILE must be set together")
	}
	if env != "dev" && tlsCert == "" {
		return nil, errors.New("AUTH_GRPC_TLS_CERT_FILE and AUTH_GRPC_TLS_KEY_FILE are required when KR0N_ENV != dev (plaintext gRPC is only allowed in dev)")
	}

	jwtIssuer := "kr0n-auth"
	if raw, ok := lookup("JWT_ISSUER"); ok && strings.TrimSpace(raw) != "" {
		jwtIssuer = strings.TrimSpace(raw)
	}

	accessTokenLifetime := 15 * time.Minute
	if raw, ok := lookup("ACCESS_TOKEN_LIFETIME"); ok && strings.TrimSpace(raw) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid ACCESS_TOKEN_LIFETIME: %w", err)
		}
		if d <= 0 {
			return nil, errors.New("ACCESS_TOKEN_LIFETIME must be positive")
		}
		accessTokenLifetime = d
	}

	refreshTokenLifetime := 30 * 24 * time.Hour
	if raw, ok := lookup("REFRESH_TOKEN_LIFETIME"); ok && strings.TrimSpace(raw) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid REFRESH_TOKEN_LIFETIME: %w", err)
		}
		if d <= 0 {
			return nil, errors.New("REFRESH_TOKEN_LIFETIME must be positive")
		}
		refreshTokenLifetime = d
	}

	emailVerificationTokenLifetime := 24 * time.Hour
	if raw, ok := lookup("EMAIL_VERIFICATION_TOKEN_LIFETIME"); ok && strings.TrimSpace(raw) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid EMAIL_VERIFICATION_TOKEN_LIFETIME: %w", err)
		}
		if d <= 0 {
			return nil, errors.New("EMAIL_VERIFICATION_TOKEN_LIFETIME must be positive")
		}
		emailVerificationTokenLifetime = d
	}

	passwordResetTokenLifetime := time.Hour
	if raw, ok := lookup("PASSWORD_RESET_TOKEN_LIFETIME"); ok && strings.TrimSpace(raw) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil || d <= 0 {
			return nil, errors.New("PASSWORD_RESET_TOKEN_LIFETIME must be a positive duration")
		}
		passwordResetTokenLifetime = d
	}

	requireVerifiedEmail := strings.EqualFold(envOr(lookup, "REQUIRE_VERIFIED_EMAIL", "false"), "true")

	return &Config{
		DatabaseURL:                    databaseURL,
		AuthGRPCAddr:                   authGRPCAddr,
		Env:                            env,
		JWTPrivateKey:                  jwtPrivateKey,
		JWTKeyID:                       envOr(lookup, "JWT_KEY_ID", "k1"),
		JWTIssuer:                      jwtIssuer,
		JWTAudience:                    envOr(lookup, "JWT_AUDIENCE", "kr0n-api"),
		AccessTokenLifetime:            accessTokenLifetime,
		RefreshTokenLifetime:           refreshTokenLifetime,
		EmailVerificationTokenLifetime: emailVerificationTokenLifetime,
		PasswordResetTokenLifetime:     passwordResetTokenLifetime,
		RequireVerifiedEmail:           requireVerifiedEmail,
		SMTPAddr:                       envOr(lookup, "SMTP_ADDR", ""),
		SMTPFrom:                       envOr(lookup, "SMTP_FROM", "noreply@kr0n.dev"),
		SMTPUsername:                   envOr(lookup, "SMTP_USERNAME", ""),
		SMTPPassword:                   envOr(lookup, "SMTP_PASSWORD", ""),
		GitHubClientID:                 envOr(lookup, "GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:             envOr(lookup, "GITHUB_CLIENT_SECRET", ""),
		GitHubRedirectURL:              envOr(lookup, "GITHUB_REDIRECT_URL", ""),
		AuthGRPCTLSCertFile:            tlsCert,
		AuthGRPCTLSKeyFile:             tlsKey,
		AuthGRPCClientCAFile:           envOr(lookup, "AUTH_GRPC_CLIENT_CA_FILE", ""),
		AuthGRPCAllowedClients:         parseCommaList(envOr(lookup, "AUTH_GRPC_ALLOWED_CLIENTS", "kr0n-gateway,gateway")),
		AuthServiceToken:               envOr(lookup, "AUTH_SERVICE_TOKEN", ""),
	}, nil
}

// LoadGateway loads configuration for the API Gateway service.
func LoadGateway() (*GatewayConfig, error) {
	return LoadGatewayFrom(os.LookupEnv)
}

// LoadGatewayFrom loads configuration for the API Gateway service using lookup.
func LoadGatewayFrom(lookup func(string) (string, bool)) (*GatewayConfig, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	gatewayHTTPAddr := ":8080"
	if raw, ok := lookup("GATEWAY_HTTP_ADDR"); ok && strings.TrimSpace(raw) != "" {
		gatewayHTTPAddr = strings.TrimSpace(raw)
	}

	authGRPCAddr := "localhost:50051"
	if raw, ok := lookup("AUTH_GRPC_ADDR"); ok && strings.TrimSpace(raw) != "" {
		authGRPCAddr = strings.TrimSpace(raw)
	}

	env := envOr(lookup, "KR0N_ENV", "dev")
	devPub := jwtkeys.DevPrivateKey().Public().(ed25519.PublicKey)

	var pubKeys map[string]ed25519.PublicKey
	if raw, ok := lookup("JWT_PUBLIC_KEYS"); ok && strings.TrimSpace(raw) != "" {
		k, err := jwtkeys.ParsePublicKeys(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT_PUBLIC_KEYS: %w", err)
		}
		if env != "dev" {
			for _, pk := range k {
				if bytes.Equal(pk, devPub) {
					return nil, errors.New("default dev JWT public key is forbidden when KR0N_ENV != dev")
				}
			}
		}
		pubKeys = k
	} else if env != "dev" {
		return nil, errors.New("JWT_PUBLIC_KEYS is required when KR0N_ENV != dev")
	} else {
		pubKeys = map[string]ed25519.PublicKey{
			envOr(lookup, "JWT_KEY_ID", "k1"): devPub,
		}
	}

	tlsCAFile := envOr(lookup, "AUTH_GRPC_TLS_CA_FILE", "")
	tlsPlain := env == "dev" && tlsCAFile == "" && !strings.EqualFold(envOr(lookup, "AUTH_GRPC_TLS_ENABLED", "false"), "true")
	if env != "dev" && tlsPlain {
		return nil, errors.New("plaintext Auth gRPC is only allowed when KR0N_ENV=dev")
	}

	var trusted []*net.IPNet
	for _, c := range strings.Split(envOr(lookup, "TRUSTED_PROXY_CIDRS", ""), ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXY_CIDRS entry %q: %w", c, err)
		}
		trusted = append(trusted, n)
	}

	genCap, err := envInt(lookup, "RATE_LIMIT_CAPACITY", 120)
	if err != nil {
		return nil, err
	}
	genRate, err := envFloat(lookup, "RATE_LIMIT_PER_SEC", 20)
	if err != nil {
		return nil, err
	}
	authCap, err := envInt(lookup, "AUTH_RATE_LIMIT_CAPACITY", 10)
	if err != nil {
		return nil, err
	}
	authRate, err := envFloat(lookup, "AUTH_RATE_LIMIT_PER_SEC", 0.2)
	if err != nil {
		return nil, err
	}

	return &GatewayConfig{
		GatewayHTTPAddr:     gatewayHTTPAddr,
		AuthGRPCAddr:        authGRPCAddr,
		Env:                 env,
		JWTPublicKeys:       pubKeys,
		JWTIssuer:           envOr(lookup, "JWT_ISSUER", "kr0n-auth"),
		JWTAudience:         envOr(lookup, "JWT_AUDIENCE", "kr0n-api"),
		RedisAddr:           envOr(lookup, "REDIS_ADDR", "localhost:6379"),
		TrustedProxies:      trusted,
		GeneralRateCapacity: genCap,
		GeneralRatePerSec:   genRate,
		AuthRateCapacity:    authCap,
		AuthRatePerSec:      authRate,
		AuthGRPCTLSCAFile:   tlsCAFile,
		AuthGRPCTLSCertFile: envOr(lookup, "GATEWAY_GRPC_TLS_CERT_FILE", envOr(lookup, "AUTH_GRPC_TLS_CERT_FILE", "")),
		AuthGRPCTLSKeyFile:  envOr(lookup, "GATEWAY_GRPC_TLS_KEY_FILE", envOr(lookup, "AUTH_GRPC_TLS_KEY_FILE", "")),
		AuthGRPCTLSPlain:    tlsPlain,
		AuthServiceToken:    envOr(lookup, "AUTH_SERVICE_TOKEN", ""),
	}, nil
}

func parseCommaList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func envOr(lookup func(string) (string, bool), key, def string) string {
	if raw, ok := lookup(key); ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw)
	}
	return def
}

func envInt(lookup func(string) (string, bool), key string, def int) (int, error) {
	raw := envOr(lookup, key, "")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return n, nil
}

func envFloat(lookup func(string) (string, bool), key string, def float64) (float64, error) {
	raw := envOr(lookup, key, "")
	if raw == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f <= 0 {
		return 0, fmt.Errorf("%s must be a positive number", key)
	}
	return f, nil
}
