package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"
)

// SpireClient defines the interface for interacting with SPIRE agents
type SpireClient interface {
	// Start initializes the client and begins receiving updates
	Start(ctx context.Context) error

	// Stop gracefully shuts down the client
	Stop() error

	// WaitForSVID waits for the specified SVID to be available
	WaitForSVID(ctx context.Context, spiffeID string, timeout time.Duration) error

	// WaitForTrustBundle waits for the trust bundle to be available
	WaitForTrustBundle(ctx context.Context, timeout time.Duration) error

	// GetCACertificates returns the current CA certificates
	GetCACertificates(ctx context.Context) ([]*x509.Certificate, error)

	// GetCertificateForIdentity returns the certificate for the specified SPIFFE ID
	GetCertificateForIdentity(spiffeID string) (*tls.Certificate, error)

	// FetchJWTSVID fetches a JWT SVID for the specified SPIFFE ID and audiences
	FetchJWTSVID(ctx context.Context, spiffeID string, audiences []string) (string, error)

	// GetTrustBundle returns the current trust bundle
	GetTrustBundle() (*x509.CertPool, error)

	// GetBundlesByDomain returns all bundles separated by domain
	GetBundlesByDomain(ctx context.Context) (map[string][]*x509.Certificate, error)

	// Status returns the connection status
	Status() (bool, string)
}
