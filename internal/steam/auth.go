package steam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"playgate/steam-token-server/internal/tokendiag"
)

const apiBase = "https://api.steampowered.com"

// ErrTokenRejected means Steam refused the refresh token (revoked, expired or the account
// was logged out manually / password changed). The caller should perform a fresh login.
var ErrTokenRejected = errors.New("refresh token rejected by steam")

// EAuthSessionGuardType
const (
	guardEmailCode  = 2
	guardDeviceCode = 3
)

// EAuthTokenPlatformType — SteamClient (for desktop client refresh tokens).
const platformSteamClient = 1

type Client struct {
	http      *http.Client
	userAgent string
	logger    *slog.Logger
}

type AuthResult struct {
	AccountName  string
	RefreshToken string
	AccessToken  string
	SteamID      string
	NewGuardData string
}

type GuardCodeFunc func(ctx context.Context) (string, error)

func NewClient(userAgent string, logger *slog.Logger) *Client {
	if userAgent == "" {
		userAgent = "PlayGateSteamTokenServer/0.1"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		http: &http.Client{
			Timeout: 45 * time.Second,
		},
		userAgent: userAgent,
		logger:    logger,
	}
}

// LoginWithCredentials performs modern Steam authentication and returns JWT tokens.
// When Steam Guard email code is required, guardCodeFn is called.
func (c *Client) LoginWithCredentials(
	ctx context.Context,
	username, password string,
	guardCodeFn GuardCodeFunc,
) (*AuthResult, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password are required")
	}

	loginStartedAt := time.Now()
	c.logger.Info("Steam credential login started", "login", username)

	rsaStartedAt := time.Now()
	rsaKey, err := c.getPasswordRSAPublicKey(ctx, username)
	if err != nil {
		c.logger.Error("Steam RSA key request failed", "login", username, "duration", time.Since(rsaStartedAt), "error", err)
		return nil, err
	}
	c.logger.Info(
		"Steam RSA key received",
		"login", username,
		"duration", time.Since(rsaStartedAt),
		"modulus_bits", rsaKey.PublicKey.BitLen(),
		"exponent", rsaKey.Exponent,
		"timestamp", rsaKey.Timestamp,
	)

	encryptedPassword, err := encryptPassword(password, rsaKey.PublicKey, rsaKey.Exponent)
	if err != nil {
		return nil, err
	}

	beginStartedAt := time.Now()
	begin, err := c.beginAuthSession(ctx, username, encryptedPassword, rsaKey.Timestamp)
	if err != nil {
		c.logger.Error("Steam begin auth failed", "login", username, "duration", time.Since(beginStartedAt), "error", err)
		return nil, err
	}
	confirmationTypes := make([]int, 0, len(begin.AllowedConfirmations))
	for _, confirmation := range begin.AllowedConfirmations {
		confirmationTypes = append(confirmationTypes, confirmation.ConfirmationType)
	}
	c.logger.Info(
		"Steam auth session started",
		"login", username,
		"duration", time.Since(beginStartedAt),
		"steam_id", begin.SteamID,
		"allowed_confirmation_types", confirmationTypes,
		tokendiag.Attr("client_id", begin.ClientID),
		tokendiag.Attr("request_id", begin.RequestID),
	)

	// If email/device code is already confirmed in allowed confirmations, submit after OTP arrives.
	needsCode := false
	for _, conf := range begin.AllowedConfirmations {
		if conf.ConfirmationType == guardEmailCode || conf.ConfirmationType == guardDeviceCode {
			needsCode = true
			break
		}
	}

	if needsCode {
		c.logger.Info(
			"Steam Guard confirmation required",
			"login", username,
			"allowed_confirmation_types", confirmationTypes,
		)
		if guardCodeFn == nil {
			return nil, fmt.Errorf("steam guard code required but no OTP provider configured")
		}
		guardStartedAt := time.Now()
		code, err := guardCodeFn(ctx)
		if err != nil {
			return nil, fmt.Errorf("steam guard otp: %w", err)
		}
		code = strings.ToUpper(strings.TrimSpace(code))
		if code == "" {
			return nil, fmt.Errorf("empty steam guard code")
		}

		codeType := guardEmailCode
		for _, conf := range begin.AllowedConfirmations {
			if conf.ConfirmationType == guardDeviceCode {
				codeType = guardDeviceCode
				break
			}
		}

		c.logger.Info(
			"submitting Steam Guard code",
			"login", username,
			"code_type", codeType,
			"code_length", len(code),
			"wait_duration", time.Since(guardStartedAt),
		)
		if err := c.submitGuardCode(ctx, begin.ClientID, begin.SteamID, code, codeType); err != nil {
			c.logger.Error("Steam Guard code submission failed", "login", username, "code_type", codeType, "error", err)
			return nil, err
		}
		c.logger.Info("Steam Guard code accepted for auth session", "login", username, "code_type", codeType)
	} else {
		c.logger.Info("Steam Guard confirmation not required", "login", username)
	}

	result, err := c.pollAuthSession(ctx, begin.ClientID, begin.RequestID)
	if err != nil {
		c.logger.Error("Steam credential login failed while polling", "login", username, "duration", time.Since(loginStartedAt), "error", err)
		return nil, err
	}
	c.logger.Info(
		"Steam credential login completed",
		"login", username,
		"duration", time.Since(loginStartedAt),
		"response_account_name", result.AccountName,
		"steam_id", result.SteamID,
		"guard_data_present", result.NewGuardData != "",
		"guard_data_length", len(result.NewGuardData),
		tokendiag.Attr("refresh_token", result.RefreshToken),
		tokendiag.Attr("access_token", result.AccessToken),
	)
	return result, nil
}

type rsaPublicKeyResponse struct {
	Response struct {
		PublicKeyMod string `json:"publickey_mod"`
		PublicKeyExp string `json:"publickey_exp"`
		Timestamp    string `json:"timestamp"`
		Success      any    `json:"success"`
	} `json:"response"`
}

type rsaKeyMaterial struct {
	PublicKey *big.Int
	Exponent  int
	Timestamp string
}

func (c *Client) getPasswordRSAPublicKey(ctx context.Context, accountName string) (*rsaKeyMaterial, error) {
	q := url.Values{}
	q.Set("account_name", accountName)
	var out rsaPublicKeyResponse
	if err := c.getJSON(ctx, "/IAuthenticationService/GetPasswordRSAPublicKey/v1/", q, &out); err != nil {
		return nil, err
	}
	mod := out.Response.PublicKeyMod
	expHex := out.Response.PublicKeyExp
	if mod == "" || expHex == "" {
		return nil, fmt.Errorf("empty RSA public key from Steam")
	}
	modInt := new(big.Int)
	if _, ok := modInt.SetString(mod, 16); !ok {
		return nil, fmt.Errorf("invalid RSA modulus")
	}
	expBytes, err := hex.DecodeString(padHex(expHex))
	if err != nil {
		return nil, fmt.Errorf("invalid RSA exponent: %w", err)
	}
	expInt := new(big.Int).SetBytes(expBytes)
	return &rsaKeyMaterial{
		PublicKey: modInt,
		Exponent:  int(expInt.Int64()),
		Timestamp: out.Response.Timestamp,
	}, nil
}

type beginAuthResponse struct {
	Response struct {
		ClientID             any     `json:"client_id"`
		RequestID            string  `json:"request_id"`
		Interval             float64 `json:"interval"`
		AllowedConfirmations []struct {
			ConfirmationType int `json:"confirmation_type"`
		} `json:"allowed_confirmations"`
		SteamID   any    `json:"steamid"`
		WeakToken string `json:"weak_token"`
	} `json:"response"`
}

type beginAuthResult struct {
	ClientID             string
	RequestID            string
	SteamID              string
	AllowedConfirmations []struct {
		ConfirmationType int
	}
}

func (c *Client) beginAuthSession(
	ctx context.Context,
	accountName, encryptedPassword, timestamp string,
) (*beginAuthResult, error) {
	form := url.Values{}
	form.Set("account_name", accountName)
	form.Set("encrypted_password", encryptedPassword)
	form.Set("encryption_timestamp", timestamp)
	form.Set("remember_login", "true")
	form.Set("platform_type", strconv.Itoa(platformSteamClient))
	form.Set("persistence", "1")
	form.Set("website_id", "Client")
	form.Set("device_friendly_name", "PlayGate Token Server")

	var out beginAuthResponse
	if err := c.postFormJSON(ctx, "/IAuthenticationService/BeginAuthSessionViaCredentials/v1/", form, &out); err != nil {
		return nil, err
	}

	res := &beginAuthResult{
		ClientID:  anyToString(out.Response.ClientID),
		RequestID: out.Response.RequestID,
		SteamID:   anyToString(out.Response.SteamID),
	}
	if res.ClientID == "" || res.RequestID == "" {
		return nil, fmt.Errorf("begin auth failed: empty client/request id")
	}
	for _, conf := range out.Response.AllowedConfirmations {
		res.AllowedConfirmations = append(res.AllowedConfirmations, struct {
			ConfirmationType int
		}{ConfirmationType: conf.ConfirmationType})
	}
	return res, nil
}

func (c *Client) submitGuardCode(ctx context.Context, clientID, steamID, code string, codeType int) error {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("steamid", steamID)
	form.Set("code", code)
	form.Set("code_type", strconv.Itoa(codeType))

	var out map[string]any
	if err := c.postFormJSON(ctx, "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/", form, &out); err != nil {
		return fmt.Errorf("submit guard code: %w", err)
	}
	return nil
}

type pollAuthResponse struct {
	Response struct {
		NewGuardData         string `json:"new_guard_data"`
		RefreshToken         string `json:"refresh_token"`
		AccessToken          string `json:"access_token"`
		AccountName          string `json:"account_name"`
		HadRemoteInteraction bool   `json:"had_remote_interaction"`
	} `json:"response"`
}

func (c *Client) pollAuthSession(ctx context.Context, clientID, requestID string) (*AuthResult, error) {
	deadline := time.Now().Add(2 * time.Minute)
	interval := 2 * time.Second
	attempt := 0

	for {
		attempt++
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("auth poll timeout")
		}

		form := url.Values{}
		form.Set("client_id", clientID)
		form.Set("request_id", requestID)

		var out pollAuthResponse
		if err := c.postFormJSON(ctx, "/IAuthenticationService/PollAuthSessionStatus/v1/", form, &out); err != nil {
			return nil, err
		}

		if out.Response.RefreshToken != "" {
			steamID := steamIDFromJWT(out.Response.RefreshToken)
			c.logger.Info(
				"Steam auth poll returned tokens",
				"attempt", attempt,
				"account_name", out.Response.AccountName,
				"steam_id", steamID,
				"had_remote_interaction", out.Response.HadRemoteInteraction,
				"guard_data_present", out.Response.NewGuardData != "",
				"guard_data_length", len(out.Response.NewGuardData),
				tokendiag.Attr("refresh_token", out.Response.RefreshToken),
				tokendiag.Attr("access_token", out.Response.AccessToken),
			)
			return &AuthResult{
				AccountName:  out.Response.AccountName,
				RefreshToken: out.Response.RefreshToken,
				AccessToken:  out.Response.AccessToken,
				SteamID:      steamID,
				NewGuardData: out.Response.NewGuardData,
			}, nil
		}
		c.logger.Info("Steam auth poll pending", "attempt", attempt, "next_poll_in", interval)

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

type generateAccessTokenResponse struct {
	Response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	} `json:"response"`
}

// ValidateRefreshToken checks a (cached) refresh token by asking Steam to mint a fresh
// access token from it via GenerateAccessTokenForApp — the same call the desktop client
// makes on start-up. A revoked/expired token (e.g. after a manual logout) is answered with
// 401/403, which is reported as ErrTokenRejected so the caller can re-login. Transient
// failures (network / 5xx) are returned as ordinary errors so callers can keep using cache
// instead of needlessly burning a Steam Guard OTP.
//
// On success it returns a freshly minted access token (may be empty on older responses).
func (c *Client) ValidateRefreshToken(ctx context.Context, refreshToken, steamID string) (string, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return "", ErrTokenRejected
	}
	if steamID == "" {
		steamID = steamIDFromJWT(refreshToken)
	}
	startedAt := time.Now()
	c.logger.Info(
		"Steam refresh-token validation started",
		"steam_id", steamID,
		tokendiag.Attr("refresh_token", refreshToken),
	)

	form := url.Values{}
	form.Set("refresh_token", refreshToken)
	form.Set("steamid", steamID)
	form.Set("renewal_type", "0") // k_EAuthTokenRenewalType_None — just validate/mint access token.

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		apiBase+"/IAuthenticationService/GenerateAccessTokenForApp/v1/",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		c.logger.Error("Steam refresh-token validation request failed", "steam_id", steamID, "duration", time.Since(startedAt), "error", err)
		return "", fmt.Errorf("validate refresh token: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		c.logger.Warn(
			"Steam rejected refresh token",
			"steam_id", steamID,
			"status", resp.StatusCode,
			"duration", time.Since(startedAt),
			tokendiag.Attr("refresh_token", refreshToken),
		)
		return "", ErrTokenRejected
	}
	if resp.StatusCode >= 400 {
		c.logger.Warn(
			"Steam refresh-token validation returned error",
			"steam_id", steamID,
			"status", resp.StatusCode,
			"duration", time.Since(startedAt),
			"response_bytes", len(raw),
		)
		return "", fmt.Errorf("validate refresh token: steam http %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(raw)), 200))
	}

	var out generateAccessTokenResponse
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return "", fmt.Errorf("validate refresh token json: %w", err)
		}
	}
	// 200 but no access token back ⇒ Steam did not honour the token.
	if out.Response.AccessToken == "" {
		c.logger.Warn(
			"Steam refresh-token validation returned no access token",
			"steam_id", steamID,
			"status", resp.StatusCode,
			"duration", time.Since(startedAt),
			tokendiag.Attr("refresh_token", refreshToken),
		)
		return "", ErrTokenRejected
	}
	c.logger.Info(
		"Steam refresh-token validation succeeded",
		"steam_id", steamID,
		"status", resp.StatusCode,
		"duration", time.Since(startedAt),
		tokendiag.Attr("refresh_token", refreshToken),
		tokendiag.Attr("access_token", out.Response.AccessToken),
	)
	return out.Response.AccessToken, nil
}

func encryptPassword(password string, mod *big.Int, exp int) (string, error) {
	pub := &rsa.PublicKey{N: mod, E: exp}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(password))
	if err != nil {
		return "", fmt.Errorf("rsa encrypt password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, dst any) error {
	u := apiBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	return c.doJSON(req, dst)
}

func (c *Client) postFormJSON(ctx context.Context, path string, form url.Values, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	return c.doJSON(req, dst)
}

func (c *Client) doJSON(req *http.Request, dst any) error {
	startedAt := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		c.logger.Error(
			"Steam API request failed",
			"method", req.Method,
			"path", req.URL.Path,
			"duration", time.Since(startedAt),
			"error", err,
		)
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	c.logger.Info(
		"Steam API response received",
		"method", req.Method,
		"path", req.URL.Path,
		"status", resp.StatusCode,
		"duration", time.Since(startedAt),
		"response_bytes", len(raw),
	)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("steam http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if dst == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("steam json: %w; body=%s", err, truncate(string(raw), 300))
	}
	return nil
}

func padHex(s string) string {
	if len(s)%2 == 1 {
		return "0" + s
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func anyToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

// steamIDFromJWT extracts "sub" from an unverified JWT payload.
func steamIDFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}
