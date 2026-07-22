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
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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
}

type AuthResult struct {
	AccountName  string
	RefreshToken string
	AccessToken  string
	SteamID      string
	NewGuardData string
}

type GuardCodeFunc func(ctx context.Context) (string, error)

func NewClient(userAgent string) *Client {
	if userAgent == "" {
		userAgent = "PlayGateSteamTokenServer/0.1"
	}
	return &Client{
		http: &http.Client{
			Timeout: 45 * time.Second,
		},
		userAgent: userAgent,
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

	rsaKey, err := c.getPasswordRSAPublicKey(ctx, username)
	if err != nil {
		return nil, err
	}

	encryptedPassword, err := encryptPassword(password, rsaKey.PublicKey, rsaKey.Exponent)
	if err != nil {
		return nil, err
	}

	begin, err := c.beginAuthSession(ctx, username, encryptedPassword, rsaKey.Timestamp)
	if err != nil {
		return nil, err
	}

	// If email/device code is already confirmed in allowed confirmations, submit after OTP arrives.
	needsCode := false
	for _, conf := range begin.AllowedConfirmations {
		if conf.ConfirmationType == guardEmailCode || conf.ConfirmationType == guardDeviceCode {
			needsCode = true
			break
		}
	}

	if needsCode {
		if guardCodeFn == nil {
			return nil, fmt.Errorf("steam guard code required but no OTP provider configured")
		}
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

		if err := c.submitGuardCode(ctx, begin.ClientID, begin.SteamID, code, codeType); err != nil {
			return nil, err
		}
	}

	return c.pollAuthSession(ctx, begin.ClientID, begin.RequestID)
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
		NewGuardData     string `json:"new_guard_data"`
		RefreshToken     string `json:"refresh_token"`
		AccessToken      string `json:"access_token"`
		AccountName      string `json:"account_name"`
		HadRemoteInteraction bool `json:"had_remote_interaction"`
	} `json:"response"`
}

func (c *Client) pollAuthSession(ctx context.Context, clientID, requestID string) (*AuthResult, error) {
	deadline := time.Now().Add(2 * time.Minute)
	interval := 2 * time.Second

	for {
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
			return &AuthResult{
				AccountName:  out.Response.AccountName,
				RefreshToken: out.Response.RefreshToken,
				AccessToken:  out.Response.AccessToken,
				SteamID:      steamID,
				NewGuardData: out.Response.NewGuardData,
			}, nil
		}

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
		return "", fmt.Errorf("validate refresh token: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", ErrTokenRejected
	}
	if resp.StatusCode >= 400 {
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
		return "", ErrTokenRejected
	}
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
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
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
