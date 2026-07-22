package tokensvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"playgate/steam-token-server/internal/otp"
	"playgate/steam-token-server/internal/steam"
	"playgate/steam-token-server/internal/store"
)

type Service struct {
	store  store.AccountStore
	steam  *steam.Client
	otp    *otp.Client
	logger *slog.Logger
}

type IssuedToken struct {
	Login        string    `json:"login"`
	SteamID      string    `json:"steamId,omitempty"`
	RefreshToken string    `json:"refreshToken"`
	AccessToken  string    `json:"accessToken,omitempty"`
	// GuardData is Steam new_guard_data (machine JWT). Desktop client needs it in
	// config.vdf RememberedMachineID or ConnectCache login stays unauthorized.
	GuardData string    `json:"guardData,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
	FromCache bool      `json:"fromCache"`
}

func New(st store.AccountStore, steamClient *steam.Client, otpClient *otp.Client, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{store: st, steam: steamClient, otp: otpClient, logger: logger}
}

// Issue returns a Steam refresh token for the launcher.
//
// Cache-first policy:
//  1. load cached session
//  2. if refresh JWT is still in date and Steam accepts it → return cache (fromCache=true)
//  3. only then perform a full Steam login (password + OTP) and persist
func (s *Service) Issue(ctx context.Context, login string, forceRefresh bool) (*IssuedToken, error) {
	acc, err := s.store.GetAccount(login)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("account not found")
		}
		return nil, err
	}
	if acc.Status != "" && acc.Status != "active" {
		return nil, fmt.Errorf("account is %s", acc.Status)
	}

	if forceRefresh {
		s.logger.Info("forceRefresh requested; skipping cache", "login", acc.Login)
	} else if issued, ok := s.tryServeCache(ctx, acc.Login); ok {
		return issued, nil
	}

	s.logger.Info("performing steam login", "login", acc.Login)

	auth, err := s.steam.LoginWithCredentials(ctx, acc.Login, acc.Password, func(ctx context.Context) (string, error) {
		s.logger.Info("requesting otp from parser", "login", acc.Login)
		res, err := s.otp.WaitForCode(ctx, acc.Login)
		if err != nil {
			return "", err
		}
		return res.Code, nil
	})
	if err != nil {
		return nil, fmt.Errorf("steam login failed: %w", err)
	}

	steamID := auth.SteamID
	if steamID == "" {
		steamID = acc.SteamID
	}
	if steamID == "" {
		steamID = steam.SteamIDFromJWT(auth.RefreshToken)
	}

	expires := steam.ExpFromJWT(auth.RefreshToken)
	if expires.IsZero() {
		expires = time.Now().UTC().Add(180 * 24 * time.Hour)
	}

	cached := store.CachedToken{
		Login:        acc.Login,
		RefreshToken: auth.RefreshToken,
		AccessToken:  auth.AccessToken,
		SteamID:      steamID,
		GuardData:    auth.NewGuardData,
		ExpiresAt:    expires,
		UpdatedAt:    time.Now().UTC(),
	}
	if err := s.store.SaveToken(cached); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}
	if strings.TrimSpace(auth.NewGuardData) == "" {
		s.logger.Warn("steam login returned empty guardData; desktop auto-login may fail", "login", acc.Login)
	}

	if steamID != "" && acc.SteamID != steamID {
		acc.SteamID = steamID
		_, _ = s.store.UpsertAccount(*acc)
	}

	s.logger.Info("issued fresh steam token", "login", acc.Login, "expiresAt", expires, "hasGuardData", strings.TrimSpace(auth.NewGuardData) != "")

	return &IssuedToken{
		Login:        acc.Login,
		SteamID:      steamID,
		RefreshToken: auth.RefreshToken,
		AccessToken:  auth.AccessToken,
		GuardData:    auth.NewGuardData,
		ExpiresAt:    expires,
		FromCache:    false,
	}, nil
}

func (s *Service) tryServeCache(ctx context.Context, login string) (*IssuedToken, bool) {
	cached, err := s.store.GetToken(login)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.logger.Info("cache miss", "login", login, "reason", "no session")
		} else {
			s.logger.Warn("cache miss", "login", login, "reason", "store error", "error", err)
		}
		return nil, false
	}
	if strings.TrimSpace(cached.RefreshToken) == "" {
		s.logger.Info("cache miss", "login", login, "reason", "empty refreshToken")
		return nil, false
	}

	expires := cached.ExpiresAt
	if expires.IsZero() {
		expires = steam.ExpFromJWT(cached.RefreshToken)
	}
	// Refresh slightly before real expiry so clients never get a near-dead JWT.
	if !expires.IsZero() && !time.Now().Before(expires.Add(-1*time.Hour)) {
		s.logger.Info("cache miss", "login", login, "reason", "expired", "expiresAt", expires)
		return nil, false
	}

	if strings.TrimSpace(cached.GuardData) == "" {
		// Desktop ConnectCache path needs machine JWT; without it a cache hit is useless.
		s.logger.Warn("cache miss", "login", login, "reason", "guardData missing")
		return nil, false
	}

	access, verr := s.steam.ValidateRefreshToken(ctx, cached.RefreshToken, cached.SteamID)
	switch {
	case verr == nil:
		if access != "" && access != cached.AccessToken {
			cached.AccessToken = access
			_ = s.store.SaveToken(*cached)
		}
	case errors.Is(verr, steam.ErrTokenRejected):
		s.logger.Warn("cache miss", "login", login, "reason", "steam rejected refresh token")
		_ = s.store.InvalidateToken(login)
		return nil, false
	default:
		// Network / Steam blip — still serve cache; JWT expiry already checked.
		s.logger.Warn("cache validate transient; serving cache", "login", login, "error", verr)
	}

	if expires.IsZero() {
		expires = time.Now().UTC().Add(180 * 24 * time.Hour)
	}

	s.logger.Info("serving cached steam token", "login", login, "expiresAt", expires)
	return &IssuedToken{
		Login:        cached.Login,
		SteamID:      cached.SteamID,
		RefreshToken: cached.RefreshToken,
		AccessToken:  cached.AccessToken,
		GuardData:    cached.GuardData,
		ExpiresAt:    expires,
		FromCache:    true,
	}, true
}
