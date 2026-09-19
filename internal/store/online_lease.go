package store

import "context"

// OnlineLease is the one-shot PlayPass online session proof the launcher sends
// to the token server. The shop refuses pool-account credentials without it.
type OnlineLease struct {
	Ticket    string
	SessionID string
	Epoch     string
}

type onlineLeaseKey struct{}

// WithOnlineLease attaches a lease to ctx. An empty ticket is ignored so offline
// envelope calls keep talking to the shop exactly as before.
func WithOnlineLease(ctx context.Context, lease OnlineLease) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if lease.Ticket == "" {
		return ctx
	}
	return context.WithValue(ctx, onlineLeaseKey{}, lease)
}

func onlineLeaseFrom(ctx context.Context) (OnlineLease, bool) {
	if ctx == nil {
		return OnlineLease{}, false
	}
	lease, ok := ctx.Value(onlineLeaseKey{}).(OnlineLease)
	if !ok || lease.Ticket == "" {
		return OnlineLease{}, false
	}
	return lease, true
}
