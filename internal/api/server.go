package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"playgate/steam-token-server/internal/store"
	"playgate/steam-token-server/internal/tokendiag"
	"playgate/steam-token-server/internal/tokensvc"
)

type Server struct {
	store         store.AccountStore
	tokens        *tokensvc.Service
	adminToken    string
	launcherToken string
	logger        *slog.Logger
}

func New(
	st store.AccountStore,
	tokens *tokensvc.Service,
	adminToken, launcherToken string,
	logger *slog.Logger,
) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:         st,
		tokens:        tokens,
		adminToken:    adminToken,
		launcherToken: launcherToken,
		logger:        logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)

	mux.HandleFunc("POST /v1/admin/steam-accounts", s.withAdmin(s.handleUpsertAccount))
	mux.HandleFunc("GET /v1/admin/steam-accounts", s.withAdmin(s.handleListAccounts))
	mux.HandleFunc("DELETE /v1/admin/steam-accounts/{login}", s.withAdmin(s.handleDeleteAccount))

	mux.HandleFunc("POST /v1/steam/tokens", s.withLauncher(s.handleIssueToken))

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type upsertAccountRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	SteamID  string `json:"steamId"`
	Status   string `json:"status"`
}

func (s *Server) handleUpsertAccount(w http.ResponseWriter, r *http.Request) {
	var req upsertAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Login) == "" {
		writeError(w, http.StatusBadRequest, "login is required")
		return
	}

	acc, err := s.store.UpsertAccount(store.Account{
		Login:    req.Login,
		Password: req.Password,
		SteamID:  req.SteamID,
		Status:   req.Status,
	})
	if err != nil {
		msg := err.Error()
		status := http.StatusBadRequest
		if strings.Contains(msg, "must be created in shop admin") {
			status = http.StatusConflict
		}
		writeError(w, status, msg)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"login":     acc.Login,
		"steamId":   acc.SteamID,
		"status":    acc.Status,
		"createdAt": acc.CreatedAt,
		"updatedAt": acc.UpdatedAt,
	})
}

func (s *Server) handleListAccounts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"items": s.store.ListAccounts(),
	})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	login := r.PathValue("login")
	if err := s.store.DeleteAccount(login); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "account not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type issueTokenRequest struct {
	Login        string `json:"login"`
	ForceRefresh bool   `json:"forceRefresh"`
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	startedAt := time.Now()
	var req issueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("launcher token request rejected: invalid JSON", "remote_addr", r.RemoteAddr, "error", err)
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Login) == "" {
		s.logger.Warn("launcher token request rejected: empty login", "remote_addr", r.RemoteAddr)
		writeError(w, http.StatusBadRequest, "login is required")
		return
	}
	s.logger.Info(
		"launcher token request received",
		"login", strings.TrimSpace(req.Login),
		"force_refresh", req.ForceRefresh,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	issued, err := s.tokens.Issue(r.Context(), req.Login, req.ForceRefresh)
	if err != nil {
		msg := err.Error()
		status := http.StatusBadGateway
		switch {
		case strings.Contains(msg, "account not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "account is"):
			status = http.StatusConflict
		case strings.Contains(msg, "otp bearerToken"):
			status = http.StatusServiceUnavailable
		}
		s.logger.Error(
			"launcher token request failed",
			"login", strings.TrimSpace(req.Login),
			"force_refresh", req.ForceRefresh,
			"status", status,
			"duration", time.Since(startedAt),
			"error", err,
		)
		writeError(w, status, msg)
		return
	}

	s.logger.Info(
		"sending token response to launcher",
		"login", issued.Login,
		"steam_id", issued.SteamID,
		"from_cache", issued.FromCache,
		"expires_at", issued.ExpiresAt,
		"duration", time.Since(startedAt),
		tokendiag.Attr("refresh_token", issued.RefreshToken),
		tokendiag.Attr("access_token", issued.AccessToken),
	)
	writeJSON(w, http.StatusOK, issued)
}

func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.withBearer(s.adminToken, next)
}

func (s *Server) withLauncher(next http.HandlerFunc) http.HandlerFunc {
	return s.withBearer(s.launcherToken, next)
}

func (s *Server) withBearer(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := bearerToken(r.Header.Get("Authorization"))
		if expected == "" || got == "" || got != expected {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error":     message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
