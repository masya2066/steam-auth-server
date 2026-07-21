package tokensvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	ExpiresAt    time.Time `json:"expiresAt"`
	FromCache    bool      `json:"fromCache"`
}

func New(st store.AccountStore, steamClient *steam.Client, otpClient *otp.Client, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{store: st, steam: steamClient, otp: otpClient, logger: logger}
}

// Issue looks up the account by Steam login and returns a refresh token.
// Uses cache when possible; otherwise logs into Steam (OTP via account otpKey if Guard is required).
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

	if !forceRefresh {
		if cached, err := s.store.GetToken(acc.Login); err == nil {
			if time.Now().Before(cached.ExpiresAt.Add(-24 * time.Hour)) {
				// A cached token can be invalidated out-of-band: the account owner may log
				// out of Steam manually or change the password, which revokes the refresh
				// token even though it has not expired. Verify it against Steam before
				// serving it; only re-login when Steam actually rejects it.
				access, verr := s.steam.ValidateRefreshToken(ctx, cached.RefreshToken, cached.SteamID)
				switch {
				case verr == nil:
					if access != "" && access != cached.AccessToken {
						cached.AccessToken = access
						_ = s.store.SaveToken(*cached)
					}
					return &IssuedToken{
						Login:        cached.Login,
						SteamID:      cached.SteamID,
						RefreshToken: cached.RefreshToken,
						AccessToken:  cached.AccessToken,
						ExpiresAt:    cached.ExpiresAt,
						FromCache:    true,
					}, nil
				case errors.Is(verr, steam.ErrTokenRejected):
					s.logger.Warn("cached refresh token was invalidated; performing fresh steam login", "login", acc.Login)
					// fall through to a full login below.
				default:
					// Transient validation failure (network / Steam 5xx). Don't burn an OTP —
					// serve the cached token and let the client try it.
					s.logger.Warn("could not validate cached token; serving cache", "login", acc.Login, "error", verr)
					return &IssuedToken{
						Login:        cached.Login,
						SteamID:      cached.SteamID,
						RefreshToken: cached.RefreshToken,
						AccessToken:  cached.AccessToken,
						ExpiresAt:    cached.ExpiresAt,
						FromCache:    true,
					}, nil
				}
			}
		}
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

	expires := time.Now().UTC().Add(180 * 24 * time.Hour)
	cached := store.CachedToken{
		Login:        acc.Login,
		RefreshToken: auth.RefreshToken,
		AccessToken:  auth.AccessToken,
		SteamID:      steamID,
		GuardData:    auth.NewGuardData,
		ExpiresAt:    expires,
	}
	if err := s.store.SaveToken(cached); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}

	if steamID != "" && acc.SteamID != steamID {
		acc.SteamID = steamID
		_, _ = s.store.UpsertAccount(*acc)
	}

	return &IssuedToken{
		Login:        acc.Login,
		SteamID:      steamID,
		RefreshToken: auth.RefreshToken,
		AccessToken:  auth.AccessToken,
		ExpiresAt:    expires,
		FromCache:    false,
	}, nil
}
