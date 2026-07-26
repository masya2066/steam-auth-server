package otp

import (
	"testing"
	"time"
)

func TestGenerateSteamGuardCode_Deterministic(t *testing.T) {
	// Well-known shared secret used in Steam TOTP fixtures (base64).
	const key = "dGVzdA==" // "test"
	at := time.Unix(0, 0)
	code, err := GenerateSteamGuardCode(key, at)
	if err != nil {
		t.Fatalf("GenerateSteamGuardCode: %v", err)
	}
	if len(code) != 5 {
		t.Fatalf("expected 5-char code, got %q", code)
	}
	code2, err := GenerateSteamGuardCode(key, at)
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}
	if code != code2 {
		t.Fatalf("not deterministic: %q vs %q", code, code2)
	}
}

func TestGenerateSteamGuardCode_Empty(t *testing.T) {
	if _, err := GenerateSteamGuardCode("   ", time.Now()); err == nil {
		t.Fatal("expected error for empty otpKey")
	}
}
