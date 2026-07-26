package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Steam Guard shared-secret alphabet (mobile authenticator).
const steamGuardAlphabet = "23456789BCDFGHJKMNPQRTVWXY"

// GenerateSteamGuardCode derives a 5-character Steam Guard code from a shared secret (otpKey).
func GenerateSteamGuardCode(otpKey string, at time.Time) (string, error) {
	secret, err := decodeSteamSharedSecret(otpKey)
	if err != nil {
		return "", err
	}
	if at.IsZero() {
		at = time.Now()
	}
	counter := uint64(at.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf[:])
	hash := mac.Sum(nil)
	offset := hash[len(hash)-1] & 0x0f
	codeInt := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	var code [5]byte
	for i := 0; i < 5; i++ {
		code[i] = steamGuardAlphabet[codeInt%uint32(len(steamGuardAlphabet))]
		codeInt /= uint32(len(steamGuardAlphabet))
	}
	return string(code[:]), nil
}

func decodeSteamSharedSecret(otpKey string) ([]byte, error) {
	otpKey = strings.TrimSpace(otpKey)
	if otpKey == "" {
		return nil, fmt.Errorf("otpKey is empty")
	}
	// Accept standard/base64url without padding.
	raw, err := base64.StdEncoding.DecodeString(otpKey)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(otpKey)
	}
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(otpKey)
	}
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(otpKey)
	}
	if err != nil {
		return nil, fmt.Errorf("decode otpKey: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("otpKey decoded empty")
	}
	return raw, nil
}
