package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAccountContextForwardsOnlineLease(t *testing.T) {
	var ticket, sessionID, epoch, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ticket = r.Header.Get("X-PlayGate-Online-Ticket")
		sessionID = r.Header.Get("X-PlayGate-Online-Session")
		epoch = r.Header.Get("X-PlayGate-Online-Epoch")
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"login":"pool","password":"secret","status":"active"}`)
	}))
	t.Cleanup(srv.Close)

	st, err := NewShopStore(srv.URL, "shop-token")
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithOnlineLease(context.Background(), OnlineLease{
		Ticket:    "ticket-1",
		SessionID: "session-1",
		Epoch:     "4",
	})
	acc, err := st.GetAccountContext(ctx, "pool")
	if err != nil {
		t.Fatal(err)
	}
	if acc.Password != "secret" {
		t.Fatalf("password=%q", acc.Password)
	}
	if ticket != "ticket-1" || sessionID != "session-1" || epoch != "4" {
		t.Fatalf("headers ticket=%q session=%q epoch=%q", ticket, sessionID, epoch)
	}
	if auth != "Bearer shop-token" {
		t.Fatalf("auth=%q", auth)
	}
}

func TestGetAccountWithoutLeaseOmitsTicket(t *testing.T) {
	var ticket string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ticket = r.Header.Get("X-PlayGate-Online-Ticket")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"login":"offline","password":"secret","status":"active"}`)
	}))
	t.Cleanup(srv.Close)

	st, err := NewShopStore(srv.URL, "shop-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAccount("offline"); err != nil {
		t.Fatal(err)
	}
	if ticket != "" {
		t.Fatalf("offline lookup forwarded ticket %q", ticket)
	}
}
