package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
)

// DualAgentClient implements SpireClient interface with two SPIRE agents
type DualAgentClient struct {
	logger  hclog.Logger
	config  Config
	client1 *Client
	client2 *Client

	// For managing concurrent operations
	cancelFunc context.CancelFunc
}

// NewDualAgentClient creates a new dual agent client
func NewDualAgentClient(logger hclog.Logger, config Config) (*DualAgentClient, error) {
	if config.SpireSocketPath2 == "" {
		return nil, errors.New("second socket path is required for dual agent client")
	}

	dac := &DualAgentClient{
		logger: logger.Named("dual-agent"),
		config: config,
	}

	config1 := config
	config1.SpireSocketPath = config.SpireSocketPath
	client1, err := New(logger.Named("agent1"), config1)
	if err != nil {
		return nil, fmt.Errorf("failed to create client1: %w", err)
	}
	dac.client1 = client1

	config2 := config
	config2.SpireSocketPath = config.SpireSocketPath2
	client2, err := New(logger.Named("agent2"), config2)
	if err != nil {
		return nil, fmt.Errorf("failed to create client2: %w", err)
	}
	dac.client2 = client2

	dac.logger.Info("dual agent client created",
		"socket1", config.SpireSocketPath,
		"socket2", config.SpireSocketPath2)

	return dac, nil
}

// Start starts both clients
func (dac *DualAgentClient) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	dac.cancelFunc = cancel

	errChan := make(chan error, 2)

	go func() {
		if err := dac.client1.Start(ctx); err != nil {
			errChan <- fmt.Errorf("client1 start failed: %w", err)
		} else {
			errChan <- nil
		}
	}()

	go func() {
		if err := dac.client2.Start(ctx); err != nil {
			errChan <- fmt.Errorf("client2 start failed: %w", err)
		} else {
			errChan <- nil
		}
	}()

	// Wait for at least one client to start successfully
	var errors []error
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			errors = append(errors, err)
			dac.logger.Warn("client failed to start", "error", err)
		}
	}

	if len(errors) == 2 {
		return fmt.Errorf("both clients failed to start: %v", errors)
	}

	dac.logger.Info("dual agent client started successfully")
	return nil
}

// WaitForSVID waits for SVID from either client
func (dac *DualAgentClient) WaitForSVID(ctx context.Context, spiffeID string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	errChan := make(chan error, 2)

	go func() {
		errChan <- dac.client1.WaitForSVID(ctx, spiffeID, timeout)
	}()

	go func() {
		errChan <- dac.client2.WaitForSVID(ctx, spiffeID, timeout)
	}()

	// Return when first client succeeds
	for i := 0; i < 2; i++ {
		select {
		case err := <-errChan:
			if err == nil {
				return nil
			}
			dac.logger.Debug("client failed to provide SVID",
				"spiffe_id", spiffeID,
				"error", err)
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SVID %s", spiffeID)
		}
	}

	return fmt.Errorf("no client could provide SVID for %s", spiffeID)
}

// WaitForTrustBundle waits for trust bundle from either client
func (dac *DualAgentClient) WaitForTrustBundle(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	errChan := make(chan error, 2)

	go func() {
		errChan <- dac.client1.WaitForTrustBundle(ctx, timeout)
	}()

	go func() {
		errChan <- dac.client2.WaitForTrustBundle(ctx, timeout)
	}()

	// Return when first client succeeds
	for i := 0; i < 2; i++ {
		select {
		case err := <-errChan:
			if err == nil {
				return nil
			}
			dac.logger.Debug("client failed to provide trust bundle", "error", err)
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for trust bundle")
		}
	}

	return fmt.Errorf("no client could provide trust bundle")
}

// GetCACertificates returns CA certificates from first available client
func (dac *DualAgentClient) GetCACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	// Try client1 first
	certs, err := dac.client1.GetCACertificates(ctx)
	if err == nil {
		return certs, nil
	}

	// Fallback to client2
	certs, err = dac.client2.GetCACertificates(ctx)
	if err == nil {
		return certs, nil
	}

	return nil, fmt.Errorf("failed to get CA certificates from any client")
}

// GetCertificateForIdentity returns certificate from first available client
func (dac *DualAgentClient) GetCertificateForIdentity(spiffeID string) (*tls.Certificate, error) {
	// Try client1 first
	cert, err := dac.client1.GetCertificateForIdentity(spiffeID)
	if err == nil {
		return cert, nil
	}

	dac.logger.Debug("client1 failed to provide certificate, trying client2",
		"spiffe_id", spiffeID,
		"error", err)

	// Fallback to client2
	cert, err = dac.client2.GetCertificateForIdentity(spiffeID)
	if err == nil {
		return cert, nil
	}

	return nil, fmt.Errorf("failed to get certificate from any client")
}

// FetchJWTSVID fetches JWT SVID from both clients concurrently
func (dac *DualAgentClient) FetchJWTSVID(ctx context.Context, spiffeID string, audiences []string) (string, error) {
	type result struct {
		token  string
		err    error
		client string
	}

	resultChan := make(chan result, 2)

	// Fetch from both clients concurrently
	go func() {
		token, err := dac.client1.FetchJWTSVID(ctx, spiffeID, audiences)
		resultChan <- result{token: token, err: err, client: "agent1"}
	}()

	go func() {
		token, err := dac.client2.FetchJWTSVID(ctx, spiffeID, audiences)
		resultChan <- result{token: token, err: err, client: "agent2"}
	}()

	// Return first successful response
	for i := 0; i < 2; i++ {
		select {
		case res := <-resultChan:
			if res.err == nil && res.token != "" {
				dac.logger.Debug("successfully fetched JWT SVID",
					"client", res.client,
					"spiffe_id", spiffeID)
				return res.token, nil
			}
			dac.logger.Warn("client failed to fetch JWT SVID",
				"client", res.client,
				"spiffe_id", spiffeID,
				"error", res.err)
		case <-time.After(30 * time.Second):
			return "", fmt.Errorf("timeout waiting for JWT SVID")
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	return "", fmt.Errorf("failed to fetch JWT SVID from any client")
}

// GetTrustBundle returns trust bundle from first available client
func (dac *DualAgentClient) GetTrustBundle() (*x509.CertPool, error) {
	bundle, err := dac.client1.GetTrustBundle()
	if err == nil {
		return bundle, nil
	}

	bundle, err = dac.client2.GetTrustBundle()
	if err == nil {
		return bundle, nil
	}

	return nil, fmt.Errorf("failed to get trust bundle from any client")
}

// Status returns combined status of both clients
func (dac *DualAgentClient) Status() (bool, string) {
	connected1, msg1 := dac.client1.Status()
	connected2, msg2 := dac.client2.Status()

	if connected1 && connected2 {
		return true, "Both agents connected"
	} else if connected1 {
		return true, fmt.Sprintf("Agent1 connected, Agent2: %s", msg2)
	} else if connected2 {
		return true, fmt.Sprintf("Agent2 connected, Agent1: %s", msg1)
	}

	return false, fmt.Sprintf("Both agents disconnected - Agent1: %s, Agent2: %s", msg1, msg2)
}

// Stop stops both clients
func (dac *DualAgentClient) Stop() error {
	dac.logger.Info("stopping dual agent client")

	if dac.cancelFunc != nil {
		dac.cancelFunc()
	}

	// Stop both clients
	var errors []error

	if err := dac.client1.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("failed to stop client1: %w", err))
	}

	if err := dac.client2.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("failed to stop client2: %w", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errors)
	}

	return nil
}
