package otp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"playgate/steam-token-server/internal/config"
)

type Client struct {
	httpClient *http.Client
	cfg        config.OTPConfig
}

type Result struct {
	Code        string
	Message     string
	Remaining   int
	CooldownSec int
}

func NewClient(cfg config.OTPConfig) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cfg:        cfg,
	}
}

// WaitForCode makes the first request after the configured initial delay, then
// makes up to two more attempts for retryable "email not found" responses.
func (c *Client) WaitForCode(ctx context.Context, login string) (*Result, error) {
	login = strings.TrimSpace(login)
	if login == "" {
		return nil, fmt.Errorf("login is required")
	}
	if strings.TrimSpace(c.cfg.BearerToken) == "" {
		return nil, fmt.Errorf("otp bearerToken is not configured")
	}

	initial := time.Duration(c.cfg.InitialDelaySec) * time.Second
	interval := time.Duration(c.cfg.PollIntervalSec) * time.Second

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(initial):
	}

	const maxAttempts = 3
	var lastMsg string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		res, retryable, err := c.requestOnce(ctx, login)
		if err != nil {
			return nil, err
		}
		if res != nil && strings.TrimSpace(res.Code) != "" {
			return res, nil
		}
		if res != nil && res.Message != "" {
			lastMsg = res.Message
		} else if retryable {
			lastMsg = "no_steam_guard_email_found"
		}

		if !retryable && res != nil {
			return nil, fmt.Errorf("otp failed: %s", firstNonEmpty(res.Message, "unknown error"))
		}

		if attempt == maxAttempts {
			break
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	return nil, fmt.Errorf(
		"otp code not found after %d attempts: %s",
		maxAttempts,
		firstNonEmpty(lastMsg, "code not ready"),
	)
}

func (c *Client) requestOnce(ctx context.Context, login string) (res *Result, retryable bool, err error) {
	url := strings.TrimRight(c.cfg.BaseURL, "/") + c.cfg.RequestPath
	body, _ := json.Marshal(map[string]string{
		"login": login,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.BearerToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("otp request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	parsed := parseOTPBody(raw)

	switch resp.StatusCode {
	case http.StatusOK:
		if strings.TrimSpace(parsed.Code) == "" {
			// 200 without code — treat as not ready and keep polling.
			return parsed, true, nil
		}
		return parsed, false, nil

	case http.StatusUnauthorized:
		return nil, false, fmt.Errorf("otp unauthorized")

	case http.StatusBadRequest:
		msg := firstNonEmpty(parsed.Message, "bad request")
		return nil, false, fmt.Errorf("otp bad request: %s", msg)

	case http.StatusNotFound:
		msg := firstNonEmpty(parsed.Message, "login not found")
		return nil, false, fmt.Errorf("otp not found: %s", msg)

	case http.StatusServiceUnavailable:
		msg := firstNonEmpty(parsed.Message, "otp service unavailable")
		return nil, false, fmt.Errorf("otp unavailable: %s", msg)

	case http.StatusBadGateway:
		// Email not arrived yet — keep polling.
		if isEmailNotFound(parsed) {
			return parsed, true, nil
		}
		msg := firstNonEmpty(parsed.Message, "bad gateway")
		return nil, false, fmt.Errorf("otp upstream error: %s", msg)

	default:
		msg := firstNonEmpty(parsed.Message, strings.TrimSpace(string(raw)))
		return nil, false, fmt.Errorf("otp http %d: %s", resp.StatusCode, msg)
	}
}

type otpBody struct {
	Code        string `json:"code"`
	GuardCode   string `json:"guardCode"`
	SteamGuard  string `json:"steamGuardCode"`
	Message     string `json:"message"`
	Error       string `json:"error"`
	Remaining   int    `json:"remaining"`
	CooldownSec int    `json:"cooldownSec"`
	Success     *bool  `json:"success"`
}

func parseOTPBody(raw []byte) *Result {
	if len(raw) == 0 {
		return &Result{}
	}
	var payload otpBody
	_ = json.Unmarshal(raw, &payload)
	code := firstNonEmpty(payload.Code, payload.GuardCode, payload.SteamGuard)
	return &Result{
		Code:        strings.TrimSpace(code),
		Message:     firstNonEmpty(payload.Message, payload.Error),
		Remaining:   payload.Remaining,
		CooldownSec: payload.CooldownSec,
	}
}

func isEmailNotFound(res *Result) bool {
	if res == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(res.Message))
	return msg == "no_steam_guard_email_found" ||
		strings.Contains(msg, "no_steam_guard_email")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
