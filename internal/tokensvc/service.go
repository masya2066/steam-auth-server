package tokensvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"playgate/steam-token-server/internal/otp"
	"playgate/steam-token-server/internal/steam"
	"playgate/steam-token-server/internal/store"
	"playgate/steam-token-server/internal/tokendiag"
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
	operationID := newOperationID()
	log := s.logger.With(
		"operation_id", operationID,
		"requested_login", login,
		"force_refresh", forceRefresh,
	)
	startedAt := time.Now()
	log.Info("token issue started")

	acc, err := s.store.GetAccount(login)
	if err != nil {
		log.Error("account lookup failed", "error", err)
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("account not found")
		}
		return nil, err
	}
	log = log.With("login", acc.Login, "account_steam_id", acc.SteamID)
	log.Info(
		"account loaded from shop",
		"status", acc.Status,
		"password_present", acc.Password != "",
		"account_updated_at", acc.UpdatedAt,
	)
	if acc.Status != "" && acc.Status != "active" {
		log.Warn("token issue rejected because account is not active", "status", acc.Status)
		return nil, fmt.Errorf("account is %s", acc.Status)
	}

	if !forceRefresh {
		log.Info("looking up cached token in shop")
		if cached, err := s.store.GetToken(acc.Login); err == nil {
			log.Info(
				"cached token loaded from shop",
				"cached_steam_id", cached.SteamID,
				"cached_expires_at", cached.ExpiresAt,
				"cached_updated_at", cached.UpdatedAt,
				"remaining", time.Until(cached.ExpiresAt),
				tokendiag.Attr("refresh_token", cached.RefreshToken),
				tokendiag.Attr("access_token", cached.AccessToken),
			)
			if time.Now().Before(cached.ExpiresAt.Add(-24 * time.Hour)) {
				// A cached token can be invalidated out-of-band: the account owner may log
				// out of Steam manually or change the password, which revokes the refresh
				// token even though it has not expired. Verify it against Steam before
				// serving it; only re-login when Steam actually rejects it.
				log.Info(
					"validating cached refresh token with Steam",
					"validation_steam_id", cached.SteamID,
					tokendiag.Attr("refresh_token", cached.RefreshToken),
				)
				validationStartedAt := time.Now()
				access, verr := s.steam.ValidateRefreshToken(ctx, cached.RefreshToken, cached.SteamID)
				switch {
				case verr == nil:
					log.Info(
						"cached refresh token accepted by Steam",
						"duration", time.Since(validationStartedAt),
						"access_token_changed", access != "" && access != cached.AccessToken,
						tokendiag.Attr("old_access_token", cached.AccessToken),
						tokendiag.Attr("new_access_token", access),
					)
					if access != "" && access != cached.AccessToken {
						cached.AccessToken = access
						if err := s.store.SaveToken(*cached); err != nil {
							log.Warn("failed to persist refreshed access token to shop", "error", err)
						} else {
							log.Info(
								"refreshed access token persisted to shop",
								tokendiag.Attr("refresh_token", cached.RefreshToken),
								tokendiag.Attr("access_token", cached.AccessToken),
							)
						}
					}
					log.Info(
						"token issue completed from cache",
						"duration", time.Since(startedAt),
						"steam_id", cached.SteamID,
						"expires_at", cached.ExpiresAt,
						tokendiag.Attr("refresh_token", cached.RefreshToken),
						tokendiag.Attr("access_token", cached.AccessToken),
					)
					return &IssuedToken{
						Login:        cached.Login,
						SteamID:      cached.SteamID,
						RefreshToken: cached.RefreshToken,
						AccessToken:  cached.AccessToken,
						ExpiresAt:    cached.ExpiresAt,
						FromCache:    true,
					}, nil
				case errors.Is(verr, steam.ErrTokenRejected):
					log.Warn(
						"cached refresh token rejected by Steam; performing fresh login",
						"duration", time.Since(validationStartedAt),
						tokendiag.Attr("refresh_token", cached.RefreshToken),
					)
					// fall through to a full login below.
				default:
					// Transient validation failure (network / Steam 5xx). Don't burn an OTP —
					// serve the cached token and let the client try it.
					log.Warn(
						"could not validate cached token; serving cache",
						"duration", time.Since(validationStartedAt),
						"error", verr,
						tokendiag.Attr("refresh_token", cached.RefreshToken),
						tokendiag.Attr("access_token", cached.AccessToken),
					)
					return &IssuedToken{
						Login:        cached.Login,
						SteamID:      cached.SteamID,
						RefreshToken: cached.RefreshToken,
						AccessToken:  cached.AccessToken,
						ExpiresAt:    cached.ExpiresAt,
						FromCache:    true,
					}, nil
				}
			} else {
				log.Warn(
					"cached token is expired or inside renewal window; performing fresh login",
					"expires_at", cached.ExpiresAt,
					"remaining", time.Until(cached.ExpiresAt),
					tokendiag.Attr("refresh_token", cached.RefreshToken),
				)
			}
		} else if errors.Is(err, store.ErrNotFound) {
			log.Info("cached token not found in shop")
		} else {
			log.Warn("cached token lookup failed; performing fresh login", "error", err)
		}
	} else {
		log.Info("cache bypassed because force refresh was requested")
	}

	log.Info("performing fresh Steam login")
	loginStartedAt := time.Now()

	auth, err := s.steam.LoginWithCredentials(ctx, acc.Login, acc.Password, func(ctx context.Context) (string, error) {
		otpStartedAt := time.Now()
		log.Info("requesting OTP from parser")
		res, err := s.otp.WaitForCode(ctx, acc.Login)
		if err != nil {
			log.Error("OTP request failed", "duration", time.Since(otpStartedAt), "error", err)
			return "", err
		}
		log.Info(
			"OTP received from parser",
			"duration", time.Since(otpStartedAt),
			"code_present", res.Code != "",
			"code_length", len(res.Code),
		)
		return res.Code, nil
	})
	if err != nil {
		log.Error("fresh Steam login failed", "duration", time.Since(loginStartedAt), "error", err)
		return nil, fmt.Errorf("steam login failed: %w", err)
	}
	log.Info(
		"fresh tokens received from Steam",
		"duration", time.Since(loginStartedAt),
		"response_account_name", auth.AccountName,
		"response_steam_id", auth.SteamID,
		"guard_data_present", auth.NewGuardData != "",
		"guard_data_length", len(auth.NewGuardData),
		tokendiag.Attr("refresh_token", auth.RefreshToken),
		tokendiag.Attr("access_token", auth.AccessToken),
	)

	steamID := auth.SteamID
	if steamID == "" {
		steamID = acc.SteamID
		log.Warn("Steam response did not contain SteamID; using account SteamID", "resolved_steam_id", steamID)
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
	log.Info(
		"saving fresh tokens to shop",
		"resolved_steam_id", steamID,
		"expires_at", expires,
		tokendiag.Attr("refresh_token", cached.RefreshToken),
		tokendiag.Attr("access_token", cached.AccessToken),
	)
	if err := s.store.SaveToken(cached); err != nil {
		log.Error("failed to save fresh tokens to shop", "error", err)
		return nil, fmt.Errorf("save token: %w", err)
	}
	log.Info(
		"fresh tokens saved to shop",
		tokendiag.Attr("refresh_token", cached.RefreshToken),
		tokendiag.Attr("access_token", cached.AccessToken),
	)

	if steamID != "" && acc.SteamID != steamID {
		log.Info("updating account SteamID in shop", "old_steam_id", acc.SteamID, "new_steam_id", steamID)
		acc.SteamID = steamID
		if _, err := s.store.UpsertAccount(*acc); err != nil {
			log.Warn("failed to update account SteamID in shop", "error", err)
		} else {
			log.Info("account SteamID updated in shop", "steam_id", steamID)
		}
	}

	log.Info(
		"token issue completed with fresh Steam login",
		"duration", time.Since(startedAt),
		"steam_id", steamID,
		"expires_at", expires,
		tokendiag.Attr("refresh_token", auth.RefreshToken),
		tokendiag.Attr("access_token", auth.AccessToken),
	)
	return &IssuedToken{
		Login:        acc.Login,
		SteamID:      steamID,
		RefreshToken: auth.RefreshToken,
		AccessToken:  auth.AccessToken,
		ExpiresAt:    expires,
		FromCache:    false,
	}, nil
}

func newOperationID() string {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}
