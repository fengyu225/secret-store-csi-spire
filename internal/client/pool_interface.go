package client

import (
	"context"
)

// ClientPoolInterface defines the interface for client pool operations
type ClientPoolInterface interface {
	AcquireClient(ctx context.Context, config Config) (SpireClient, error)
	ReleaseClient(config Config)
	Shutdown() error
	GetPoolStats() map[string]interface{}
}
