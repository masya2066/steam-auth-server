package store

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// FileAccountStore is a local JSON map of Steam accounts for offline/dev probes.
// Shape: { "<login>": { "login", "password", "otpKey?", "steamId?", "status?", ... }, ... }
type FileAccountStore struct {
	path string
	mu   sync.Mutex
}

func NewFileAccountStore(path string) (*FileAccountStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("accounts file path is required")
	}
	st := &FileAccountStore{path: path}
	if _, err := st.load(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *FileAccountStore) UpsertAccount(acc Account) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.load()
	if err != nil {
		return nil, err
	}
	login := normalizeLogin(acc.Login)
	if login == "" {
		return nil, fmt.Errorf("login is required")
	}
	now := time.Now().UTC()
	existing, ok := m[login]
	if !ok {
		existing = Account{Login: login, CreatedAt: now}
	}
	if acc.Password != "" {
		existing.Password = acc.Password
	}
	if acc.OTPKey != "" {
		existing.OTPKey = acc.OTPKey
	}
	if acc.SteamID != "" {
		existing.SteamID = acc.SteamID
	}
	if acc.Status != "" {
		existing.Status = acc.Status
	}
	if existing.Status == "" {
		existing.Status = "active"
	}
	existing.Login = login
	existing.UpdatedAt = now
	m[login] = existing
	if err := s.save(m); err != nil {
		return nil, err
	}
	out := existing
	return &out, nil
}

func (s *FileAccountStore) GetAccount(login string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.load()
	if err != nil {
		return nil, err
	}
	login = normalizeLogin(login)
	acc, ok := m[login]
	if !ok {
		return nil, ErrNotFound
	}
	out := acc
	return &out, nil
}

func (s *FileAccountStore) ListAccounts() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.load()
	if err != nil {
		return nil
	}
	items := make([]Account, 0, len(m))
	for _, acc := range m {
		acc.Password = ""
		acc.OTPKey = ""
		items = append(items, acc)
	}
	return items
}

func (s *FileAccountStore) DeleteAccount(login string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.load()
	if err != nil {
		return err
	}
	login = normalizeLogin(login)
	if _, ok := m[login]; !ok {
		return ErrNotFound
	}
	delete(m, login)
	return s.save(m)
}

func (s *FileAccountStore) GetToken(login string) (*CachedToken, error) {
	return nil, ErrNotFound
}

func (s *FileAccountStore) SaveToken(tok CachedToken) error {
	return nil
}

func (s *FileAccountStore) InvalidateToken(login string) error {
	return nil
}

func (s *FileAccountStore) load() (map[string]Account, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Account{}, nil
		}
		return nil, fmt.Errorf("read accounts file: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]Account{}, nil
	}

	var asMap map[string]Account
	if err := json.Unmarshal(raw, &asMap); err == nil && asMap != nil {
		out := make(map[string]Account, len(asMap))
		for k, v := range asMap {
			login := normalizeLogin(firstNonEmpty(v.Login, k))
			v.Login = login
			if v.Status == "" {
				v.Status = "active"
			}
			out[login] = v
		}
		return out, nil
	}

	var asList []Account
	if err := json.Unmarshal(raw, &asList); err != nil {
		return nil, fmt.Errorf("parse accounts file: %w", err)
	}
	out := make(map[string]Account, len(asList))
	for _, v := range asList {
		login := normalizeLogin(v.Login)
		if login == "" {
			continue
		}
		v.Login = login
		if v.Status == "" {
			v.Status = "active"
		}
		out[login] = v
	}
	return out, nil
}

func (s *FileAccountStore) save(m map[string]Account) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
