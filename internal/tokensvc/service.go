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
	// Deprecated for desktop silent login: VPS-issued GuardData is rejected on end-user PCs.
	GuardData string    `json:"guardData,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
	FromCache bool      `json:"fromCache"`
}

// PasswordEnvelope is returned by IssueEnvelope for client-side Steam BeginAuth.
type PasswordEnvelope struct {
	Login               string    `json:"login"`
	SteamID             string    `json:"steamId,omitempty"`
	EncryptedPassword   string    `json:"encryptedPassword"`
	EncryptionTimestamp string    `json:"encryptionTimestamp"`
	ExpiresAt           time.Time `json:"expiresAt"`
}

// OtpCode is a temporary Steam Guard email/device code from the OTP parser.
type OtpCode struct {
	Login string `json:"login"`
	Code  string `json:"code"`
}

func New(st store.AccountStore, steamClient *steam.Client, otpClient *otp.Client, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{store: st, steam: steamClient, otp: otpClient, logger: logger}
}

// IssueEnvelope returns a short-lived RSA-encrypted password for the launcher to complete
// Steam auth on the end-user PC (local machine_id / GuardData). Prefer this over Issue.
func (s *Service) IssueEnvelope(ctx context.Context, login string) (*PasswordEnvelope, error) {
	acc, err := s.activeAccount(login)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(acc.Password) == "" {
		return nil, fmt.Errorf("account password is empty")
	}

	s.logger.Info("issuing password envelope for client steam auth", "login", acc.Login)
	env, err := s.steam.CreatePasswordEnvelope(ctx, acc.Login, acc.Password, acc.SteamID)
	if err != nil {
		return nil, fmt.Errorf("create password envelope: %w", err)
	}

	return &PasswordEnvelope{
		Login:               env.AccountName,
		SteamID:             env.SteamID,
		EncryptedPassword:   env.EncryptedPassword,
		EncryptionTimestamp: env.EncryptionTimestamp,
		ExpiresAt:           env.ExpiresAt,
	}, nil
}

// RequestOtp returns a Steam Guard code.
// codeType: 2 = email (parser), 3 = device/mobile (otpKey TOTP when available).
// When codeType is 0/unknown, prefer otpKey if present, else email parser.
func (s *Service) RequestOtp(ctx context.Context, login string, codeType int) (*OtpCode, error) {
	acc, err := s.activeAccount(login)
	if err != nil {
		return nil, err
	}

	useTotp := strings.TrimSpace(acc.OTPKey) != "" && (codeType == 0 || codeType == 3)
	if codeType == 2 {
		useTotp = false
	}

	if useTotp {
		code, err := otp.GenerateSteamGuardCode(acc.OTPKey, time.Now())
		if err != nil {
			return nil, fmt.Errorf("generate steam guard from otpKey: %w", err)
		}
		s.logger.Info("generated steam guard code from otpKey", "login", acc.Login, "codeType", codeType)
		return &OtpCode{Login: acc.Login, Code: code}, nil
	}

	s.logger.Info("requesting otp from parser for client steam auth", "login", acc.Login, "codeType", codeType)
	res, err := s.otp.WaitForCode(ctx, acc.Login)
	if err != nil {
		return nil, err
	}
	code := strings.ToUpper(strings.TrimSpace(res.Code))
	if code == "" {
		return nil, fmt.Errorf("empty steam guard code")
	}
	return &OtpCode{Login: acc.Login, Code: code}, nil
}

func (s *Service) activeAccount(login string) (*store.Account, error) {
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
	return acc, nil
}

// Issue looks up the account by Steam login and returns a refresh token.
// Deprecated for desktop silent login: tokens/GuardData are issued on the VPS and rejected
// on end-user PCs (Invalid Password). Prefer IssueEnvelope + client-side Steam auth.
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
					// Desktop Steam needs machine guard data alongside the refresh JWT.
					// If the shop session was saved without it, force a fresh login.
					if strings.TrimSpace(cached.GuardData) == "" {
						s.logger.Warn("cached token has no guardData; performing fresh steam login", "login", acc.Login)
						break
					}
					return &IssuedToken{
						Login:        cached.Login,
						SteamID:      cached.SteamID,
						RefreshToken: cached.RefreshToken,
						AccessToken:  cached.AccessToken,
						GuardData:    cached.GuardData,
						ExpiresAt:    cached.ExpiresAt,
						FromCache:    true,
					}, nil
				case errors.Is(verr, steam.ErrTokenRejected):
					s.logger.Warn("cached refresh token was invalidated; performing fresh steam login", "login", acc.Login)
					// fall through to a full login below.
				default:
					// Transient validation failure (network / Steam 5xx). Don't burn an OTP —
					// serve the cached token and let the client try it (only if guardData present).
					if strings.TrimSpace(cached.GuardData) == "" {
						s.logger.Warn("could not validate cached token and guardData missing; performing fresh steam login", "login", acc.Login, "error", verr)
						break
					}
					s.logger.Warn("could not validate cached token; serving cache", "login", acc.Login, "error", verr)
					return &IssuedToken{
						Login:        cached.Login,
						SteamID:      cached.SteamID,
						RefreshToken: cached.RefreshToken,
						AccessToken:  cached.AccessToken,
						GuardData:    cached.GuardData,
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
		GuardData:    auth.NewGuardData,
		ExpiresAt:    expires,
		FromCache:    false,
	}, nil
}
