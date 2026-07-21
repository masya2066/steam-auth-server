package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"playgate/steam-token-server/internal/api"
	"playgate/steam-token-server/internal/config"
	"playgate/steam-token-server/internal/otp"
	"playgate/steam-token-server/internal/steam"
	"playgate/steam-token-server/internal/store"
	"playgate/steam-token-server/internal/tokensvc"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config yaml")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	st, err := store.NewShopStore(cfg.Store.BaseURL, cfg.Store.BearerToken, logger)
	if err != nil {
		logger.Error("failed to init shop store", "error", err)
		os.Exit(1)
	}

	steamClient := steam.NewClient(cfg.Steam.UserAgent, logger)
	otpClient := otp.NewClient(cfg.OTP)
	tokenService := tokensvc.New(st, steamClient, otpClient, logger)
	server := api.New(st, tokenService, cfg.AdminToken, cfg.LauncherToken, logger)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("steam token server listening", "addr", cfg.ListenAddr, "store", cfg.Store.BaseURL)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
