package store

import (
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

type Account struct {
	Login     string    `json:"login"`
	Password  string    `json:"password"`
	OTPKey    string    `json:"otpKey,omitempty"`
	SteamID   string    `json:"steamId,omitempty"`
	Status    string    `json:"status"` // active | disabled
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type CachedToken struct {
	Login        string    `json:"login"`
	RefreshToken string    `json:"refreshToken"`
	AccessToken  string    `json:"accessToken,omitempty"`
	SteamID      string    `json:"steamId,omitempty"`
	GuardData    string    `json:"guardData,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// AccountStore is the persistence backend for Steam accounts and JWT cache.
type AccountStore interface {
	UpsertAccount(acc Account) (*Account, error)
	GetAccount(login string) (*Account, error)
	ListAccounts() []Account
	DeleteAccount(login string) error
	GetToken(login string) (*CachedToken, error)
	SaveToken(tok CachedToken) error
	InvalidateToken(login string) error
}
