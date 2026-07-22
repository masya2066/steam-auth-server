package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr    string      `yaml:"listenAddr"`
	AdminToken    string      `yaml:"adminToken"`
	LauncherToken string      `yaml:"launcherToken"`
	OTP           OTPConfig   `yaml:"otp"`
	Steam         SteamConfig `yaml:"steam"`
	Store         StoreConfig `yaml:"store"`
}

type OTPConfig struct {
	BaseURL         string `yaml:"baseURL"`
	RequestPath     string `yaml:"requestPath"`
	BearerToken     string `yaml:"bearerToken"`
	InitialDelaySec int    `yaml:"initialDelaySec"`
	PollIntervalSec int    `yaml:"pollIntervalSec"`
	PollTimeoutSec  int    `yaml:"pollTimeoutSec"`
}

type SteamConfig struct {
	UserAgent string `yaml:"userAgent"`
}

// StoreConfig points at the shop internal API used as account/session storage.
// When baseURL/bearerToken are empty, otp.baseURL / otp.bearerToken are reused.
type StoreConfig struct {
	BaseURL        string `yaml:"baseURL"`
	BearerToken    string `yaml:"bearerToken"`
	LocalCachePath string `yaml:"localCachePath"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Default() *Config {
	cfg := &Config{
		ListenAddr:    ":8088",
		AdminToken:    "change-me-admin",
		LauncherToken: "change-me-launcher",
		OTP: OTPConfig{
			BaseURL:         "https://playgate.store",
			RequestPath:     "/api/internal/steam-guard/request-by-login",
			InitialDelaySec: 5,
			PollIntervalSec: 3,
			PollTimeoutSec:  90,
		},
		Steam: SteamConfig{
			UserAgent: "PlayGateSteamTokenServer/0.1",
		},
		Store: StoreConfig{},
	}
	cfg.applyDefaults()
	return cfg
}

func (c *Config) applyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8088"
	}
	if c.OTP.RequestPath == "" {
		c.OTP.RequestPath = "/api/internal/steam-guard/request-by-login"
	}
	if c.OTP.InitialDelaySec <= 0 {
		c.OTP.InitialDelaySec = 5
	}
	if c.OTP.PollIntervalSec <= 0 {
		c.OTP.PollIntervalSec = 3
	}
	if c.OTP.PollTimeoutSec <= 0 {
		c.OTP.PollTimeoutSec = 90
	}
	if c.Steam.UserAgent == "" {
		c.Steam.UserAgent = "PlayGateSteamTokenServer/0.1"
	}
	if c.Store.BaseURL == "" {
		c.Store.BaseURL = c.OTP.BaseURL
	}
	if c.Store.BearerToken == "" {
		c.Store.BearerToken = c.OTP.BearerToken
	}
	if strings.TrimSpace(c.Store.LocalCachePath) == "" {
		c.Store.LocalCachePath = "data/token-cache.json"
	}
}

func (c *Config) validate() error {
	if c.AdminToken == "" || c.AdminToken == "change-me-admin" {
		return fmt.Errorf("adminToken must be set to a non-default value")
	}
	if c.LauncherToken == "" || c.LauncherToken == "change-me-launcher" {
		return fmt.Errorf("launcherToken must be set to a non-default value")
	}
	if c.OTP.BaseURL == "" {
		return fmt.Errorf("otp.baseURL is required")
	}
	if strings.TrimSpace(c.OTP.BearerToken) == "" {
		return fmt.Errorf("otp.bearerToken is required (permanent token for OTP parser)")
	}
	if strings.TrimSpace(c.Store.BaseURL) == "" {
		return fmt.Errorf("store.baseURL is required (or set otp.baseURL)")
	}
	if strings.TrimSpace(c.Store.BearerToken) == "" {
		return fmt.Errorf("store.bearerToken is required (or set otp.bearerToken)")
	}
	return nil
}
