package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ShopStore persists accounts and Steam JWT sessions via playgate shop internal API.
type ShopStore struct {
	httpClient  *http.Client
	baseURL     string
	bearerToken string
}

func NewShopStore(baseURL, bearerToken string) (*ShopStore, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	bearerToken = strings.TrimSpace(bearerToken)
	if baseURL == "" {
		return nil, fmt.Errorf("shop store baseURL is required")
	}
	if bearerToken == "" {
		return nil, fmt.Errorf("shop store bearerToken is required")
	}
	return &ShopStore{
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		baseURL:     baseURL,
		bearerToken: bearerToken,
	}, nil
}

func (s *ShopStore) UpsertAccount(acc Account) (*Account, error) {
	login := normalizeLogin(acc.Login)
	if login == "" {
		return nil, fmt.Errorf("login is required")
	}

	existing, err := s.GetAccount(login)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("account %q must be created in shop admin with mail credentials first", login)
		}
		return nil, err
	}

	body := map[string]string{
		"login": login,
	}
	if acc.Password != "" {
		body["steamPassword"] = acc.Password
	}
	if acc.SteamID != "" {
		body["steamId"] = acc.SteamID
	}
	if acc.Status != "" {
		body["status"] = acc.Status
	}

	var out shopAccountDTO
	if err := s.do(context.Background(), http.MethodPatch, "/api/internal/steam-auth/account", body, &out); err != nil {
		return nil, err
	}
	updated := out.toAccount()
	if acc.Password != "" {
		updated.Password = acc.Password
	} else {
		updated.Password = existing.Password
	}
	return &updated, nil
}

func (s *ShopStore) GetAccount(login string) (*Account, error) {
	login = normalizeLogin(login)
	if login == "" {
		return nil, fmt.Errorf("login is required")
	}
	var out shopAccountDTO
	err := s.do(context.Background(), http.MethodGet, "/api/internal/steam-auth/account?login="+url.QueryEscape(login), nil, &out)
	if err != nil {
		return nil, err
	}
	acc := out.toAccount()
	return &acc, nil
}

func (s *ShopStore) ListAccounts() []Account {
	var out struct {
		Items []shopAccountListDTO `json:"items"`
	}
	if err := s.do(context.Background(), http.MethodGet, "/api/internal/steam-auth/accounts", nil, &out); err != nil {
		return nil
	}
	items := make([]Account, 0, len(out.Items))
	for _, item := range out.Items {
		acc := item.toAccount()
		acc.Password = ""
		items = append(items, acc)
	}
	return items
}

func (s *ShopStore) DeleteAccount(login string) error {
	login = normalizeLogin(login)
	if login == "" {
		return fmt.Errorf("login is required")
	}
	return s.do(context.Background(), http.MethodDelete, "/api/internal/steam-auth/account?login="+url.QueryEscape(login), nil, nil)
}

func (s *ShopStore) GetToken(login string) (*CachedToken, error) {
	login = normalizeLogin(login)
	if login == "" {
		return nil, fmt.Errorf("login is required")
	}
	var out shopSessionDTO
	err := s.do(context.Background(), http.MethodGet, "/api/internal/steam-auth/session?login="+url.QueryEscape(login), nil, &out)
	if err != nil {
		return nil, err
	}
	tok := out.toCachedToken()
	return &tok, nil
}

func (s *ShopStore) SaveToken(tok CachedToken) error {
	login := normalizeLogin(tok.Login)
	if login == "" || tok.RefreshToken == "" {
		return fmt.Errorf("login and refreshToken are required")
	}
	expiresAt := tok.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(180 * 24 * time.Hour)
	}
	body := map[string]string{
		"login":        login,
		"refreshToken": tok.RefreshToken,
		"accessToken":  tok.AccessToken,
		"steamId":      tok.SteamID,
		"guardData":    tok.GuardData,
		"expiresAt":    expiresAt.UTC().Format(time.RFC3339),
	}
	return s.do(context.Background(), http.MethodPut, "/api/internal/steam-auth/session", body, nil)
}

func (s *ShopStore) InvalidateToken(login string) error {
	login = normalizeLogin(login)
	if login == "" {
		return fmt.Errorf("login is required")
	}
	return s.do(context.Background(), http.MethodDelete, "/api/internal/steam-auth/session?login="+url.QueryEscape(login), nil, nil)
}

type shopAccountDTO struct {
	ID        string `json:"id"`
	Login     string `json:"login"`
	Password  string `json:"password"`
	SteamID   string `json:"steamId"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type shopAccountListDTO struct {
	ID        string `json:"id"`
	Login     string `json:"login"`
	SteamID   string `json:"steamId"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type shopSessionDTO struct {
	Login        string `json:"login"`
	RefreshToken string `json:"refreshToken"`
	AccessToken  string `json:"accessToken"`
	SteamID      string `json:"steamId"`
	GuardData    string `json:"guardData"`
	ExpiresAt    string `json:"expiresAt"`
	UpdatedAt    string `json:"updatedAt"`
}

func (d shopAccountDTO) toAccount() Account {
	return Account{
		Login:     d.Login,
		Password:  d.Password,
		SteamID:   d.SteamID,
		Status:    firstNonEmpty(d.Status, "active"),
		CreatedAt: parseFlexibleTime(d.CreatedAt),
		UpdatedAt: parseFlexibleTime(d.UpdatedAt),
	}
}

func (d shopAccountListDTO) toAccount() Account {
	return Account{
		Login:     d.Login,
		SteamID:   d.SteamID,
		Status:    firstNonEmpty(d.Status, "active"),
		CreatedAt: parseFlexibleTime(d.CreatedAt),
		UpdatedAt: parseFlexibleTime(d.UpdatedAt),
	}
}

func (d shopSessionDTO) toCachedToken() CachedToken {
	return CachedToken{
		Login:        d.Login,
		RefreshToken: d.RefreshToken,
		AccessToken:  d.AccessToken,
		SteamID:      d.SteamID,
		GuardData:    d.GuardData,
		ExpiresAt:    parseFlexibleTime(d.ExpiresAt),
		UpdatedAt:    parseFlexibleTime(d.UpdatedAt),
	}
}

func (s *ShopStore) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.bearerToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("shop store request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		if out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("shop store decode: %w", err)
			}
		}
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusUnauthorized:
		return fmt.Errorf("shop store unauthorized")
	case http.StatusServiceUnavailable:
		return fmt.Errorf("shop store unavailable: %s", firstNonEmpty(extractError(raw), "service unavailable"))
	default:
		return fmt.Errorf("shop store http %d: %s", resp.StatusCode, firstNonEmpty(extractError(raw), strings.TrimSpace(string(raw))))
	}
}

func extractError(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &payload)
	return firstNonEmpty(payload.Error, payload.Message)
}

func parseFlexibleTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"02.01.2006 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return t
		}
	}
	return time.Time{}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func normalizeLogin(login string) string {
	b := make([]byte, 0, len(login))
	started := false
	for i := 0; i < len(login); i++ {
		c := login[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if !started {
				continue
			}
			b = append(b, c)
			continue
		}
		started = true
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		b = append(b, c)
	}
	for len(b) > 0 {
		last := b[len(b)-1]
		if last == ' ' || last == '\t' || last == '\n' || last == '\r' {
			b = b[:len(b)-1]
			continue
		}
		break
	}
	return string(b)
}
