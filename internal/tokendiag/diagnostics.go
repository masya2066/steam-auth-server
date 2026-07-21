package tokendiag

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

// Attr returns safe, comparable token diagnostics without exposing the token itself.
// The short fingerprint matches the first 16 SHA-256 hex characters logged by the launcher.
func Attr(name, token string) slog.Attr {
	sum := sha256.Sum256([]byte(token))
	fullHash := hex.EncodeToString(sum[:])
	claims, isJWT := parseJWTClaims(token)

	attrs := []any{
		"present", token != "",
		"length", len(token),
		"fingerprint", fullHash[:16],
		"sha256", fullHash,
		"jwt", isJWT,
	}
	if claims.Subject != "" {
		attrs = append(attrs, "sub", claims.Subject)
	}
	if claims.Issuer != "" {
		attrs = append(attrs, "iss", claims.Issuer)
	}
	if claims.Audience != "" {
		attrs = append(attrs, "aud", claims.Audience)
	}
	if !claims.IssuedAt.IsZero() {
		attrs = append(attrs, "iat", claims.IssuedAt)
	}
	if !claims.ExpiresAt.IsZero() {
		attrs = append(attrs, "exp", claims.ExpiresAt)
	}

	return slog.Group(name, attrs...)
}

type jwtClaims struct {
	Subject   string
	Issuer    string
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func parseJWTClaims(token string) (jwtClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, false
	}

	var raw struct {
		Subject  json.RawMessage `json:"sub"`
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
		IssuedAt int64           `json:"iat"`
		Expires  int64           `json:"exp"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return jwtClaims{}, false
	}

	claims := jwtClaims{
		Subject:  rawValue(raw.Subject),
		Issuer:   raw.Issuer,
		Audience: rawValue(raw.Audience),
	}
	if raw.IssuedAt > 0 {
		claims.IssuedAt = time.Unix(raw.IssuedAt, 0).UTC()
	}
	if raw.Expires > 0 {
		claims.ExpiresAt = time.Unix(raw.Expires, 0).UTC()
	}
	return claims, true
}

func rawValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	return string(raw)
}
