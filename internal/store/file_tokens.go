package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileTokenStore is a local JWT session cache (refresh + guardData) used as a
// durable overlay when the remote shop session API drops fields or is briefly down.
type FileTokenStore struct {
	path string
	mu   sync.Mutex
}

func NewFileTokenStore(path string) (*FileTokenStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("file token cache path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create token cache dir: %w", err)
	}
	return &FileTokenStore{path: path}, nil
}

func (f *FileTokenStore) GetToken(login string) (*CachedToken, error) {
	login = normalizeLogin(login)
	f.mu.Lock()
	defer f.mu.Unlock()

	m, err := f.readAllUnlocked()
	if err != nil {
		return nil, err
	}
	tok, ok := m[login]
	if !ok || strings.TrimSpace(tok.RefreshToken) == "" {
		return nil, ErrNotFound
	}
	cp := tok
	return &cp, nil
}

func (f *FileTokenStore) SaveToken(tok CachedToken) error {
	login := normalizeLogin(tok.Login)
	if login == "" || strings.TrimSpace(tok.RefreshToken) == "" {
		return fmt.Errorf("login and refreshToken are required")
	}
	tok.Login = login
	tok.UpdatedAt = time.Now().UTC()
	if tok.ExpiresAt.IsZero() {
		tok.ExpiresAt = time.Now().UTC().Add(180 * 24 * time.Hour)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	m, err := f.readAllUnlocked()
	if err != nil {
		return err
	}
	m[login] = tok
	return f.writeAllUnlocked(m)
}

func (f *FileTokenStore) InvalidateToken(login string) error {
	login = normalizeLogin(login)
	f.mu.Lock()
	defer f.mu.Unlock()

	m, err := f.readAllUnlocked()
	if err != nil {
		return err
	}
	if _, ok := m[login]; !ok {
		return nil
	}
	delete(m, login)
	return f.writeAllUnlocked(m)
}

func (f *FileTokenStore) readAllUnlocked() (map[string]CachedToken, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]CachedToken{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]CachedToken{}, nil
	}
	var m map[string]CachedToken
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse token cache: %w", err)
	}
	if m == nil {
		m = map[string]CachedToken{}
	}
	return m, nil
}

func (f *FileTokenStore) writeAllUnlocked(m map[string]CachedToken) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}
