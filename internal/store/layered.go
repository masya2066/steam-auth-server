package store

import (
	"errors"
	"strings"
	"time"
)

// LayeredStore keeps accounts on the remote shop API and merges JWT sessions
// from remote + local file cache. Local cache preserves guardData when shop
// omit/drops it on read-back.
type LayeredStore struct {
	remote AccountStore
	local  *FileTokenStore
}

func NewLayeredStore(remote AccountStore, local *FileTokenStore) *LayeredStore {
	return &LayeredStore{remote: remote, local: local}
}

func (s *LayeredStore) UpsertAccount(acc Account) (*Account, error) {
	return s.remote.UpsertAccount(acc)
}

func (s *LayeredStore) GetAccount(login string) (*Account, error) {
	return s.remote.GetAccount(login)
}

func (s *LayeredStore) ListAccounts() []Account {
	return s.remote.ListAccounts()
}

func (s *LayeredStore) DeleteAccount(login string) error {
	_ = s.local.InvalidateToken(login)
	return s.remote.DeleteAccount(login)
}

func (s *LayeredStore) GetToken(login string) (*CachedToken, error) {
	login = normalizeLogin(login)

	local, localErr := s.local.GetToken(login)
	remote, remoteErr := s.remote.GetToken(login)

	switch {
	case localErr == nil && remoteErr == nil:
		return mergeTokens(local, remote), nil
	case localErr == nil:
		return local, nil
	case remoteErr == nil:
		return remote, nil
	case errors.Is(localErr, ErrNotFound) && errors.Is(remoteErr, ErrNotFound):
		return nil, ErrNotFound
	case remoteErr != nil && !errors.Is(remoteErr, ErrNotFound):
		// Remote failure but local hit already handled; both failed.
		if localErr != nil && !errors.Is(localErr, ErrNotFound) {
			return nil, remoteErr
		}
		return nil, remoteErr
	default:
		return nil, ErrNotFound
	}
}

func (s *LayeredStore) SaveToken(tok CachedToken) error {
	localErr := s.local.SaveToken(tok)
	remoteErr := s.remote.SaveToken(tok)
	if localErr != nil {
		return localErr
	}
	// Remote save is best-effort for cache durability; local already has a copy.
	if remoteErr != nil {
		return nil
	}
	return nil
}

func (s *LayeredStore) InvalidateToken(login string) error {
	_ = s.local.InvalidateToken(login)
	return s.remote.InvalidateToken(login)
}

func mergeTokens(a, b *CachedToken) *CachedToken {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}

	out := *a
	// Prefer whichever side still has guardData / richer fields.
	if strings.TrimSpace(out.GuardData) == "" && strings.TrimSpace(b.GuardData) != "" {
		out.GuardData = b.GuardData
	}
	if strings.TrimSpace(out.RefreshToken) == "" && strings.TrimSpace(b.RefreshToken) != "" {
		out.RefreshToken = b.RefreshToken
		out.AccessToken = b.AccessToken
		out.SteamID = b.SteamID
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		out.AccessToken = b.AccessToken
	}
	if strings.TrimSpace(out.SteamID) == "" {
		out.SteamID = b.SteamID
	}
	// Prefer the newer expiry when both are set.
	if b.ExpiresAt.After(out.ExpiresAt) {
		out.ExpiresAt = b.ExpiresAt
	}
	if b.UpdatedAt.After(out.UpdatedAt) {
		out.UpdatedAt = b.UpdatedAt
	}
	// If remote refresh is newer (by UpdatedAt) and non-empty, prefer it.
	if b.UpdatedAt.After(a.UpdatedAt) && strings.TrimSpace(b.RefreshToken) != "" &&
		!b.UpdatedAt.IsZero() && !a.UpdatedAt.IsZero() {
		out.RefreshToken = b.RefreshToken
		if strings.TrimSpace(b.AccessToken) != "" {
			out.AccessToken = b.AccessToken
		}
		if strings.TrimSpace(b.GuardData) != "" {
			out.GuardData = b.GuardData
		}
		if strings.TrimSpace(b.SteamID) != "" {
			out.SteamID = b.SteamID
		}
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = time.Now().UTC().Add(180 * 24 * time.Hour)
	}
	return &out
}
