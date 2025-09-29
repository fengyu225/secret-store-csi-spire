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
	client1 SpireClient
	client2 SpireClient

	// For managing concurrent operations
	cancelFunc context.CancelFunc
}

// NewDualAgentClient creates a new dual agent client
func NewDualAgentClient(logger hclog.Logger, config Config) (*DualAgentClient, error) {
	if config.SpireSocketPath2 == "" {
		return nil, errors.New("second socket path is required for dual agent client")
	}

	if config.SpireSocketPath == config.SpireSocketPath2 {
		return nil, errors.New("socket paths must be different for dual agent redundancy")
	}

	dac := &DualAgentClient{
		logger: logger.Named("dual-agent"),
		config: config,
	}

	config1 := config
	config1.SpireSocketPath = config.SpireSocketPath
	config1.AgentID = "agent1"
	client1, err := New(logger.Named("agent1"), config1)
	if err != nil {
		return nil, fmt.Errorf("failed to create client1: %w", err)
	}
	dac.client1 = client1

	config2 := config
	config2.SpireSocketPath = config.SpireSocketPath2
	config2.AgentID = "agent2"
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
		ctx1, cancel1 := context.WithCancel(ctx)
		if err := dac.client1.Start(ctx1); err != nil {
			errChan <- fmt.Errorf("client1 start failed: %w", err)
			cancel1()
		} else {
			errChan <- nil
			cancel1()
		}
	}()

	go func() {
		ctx2, cancel2 := context.WithCancel(ctx)
		if err := dac.client2.Start(ctx2); err != nil {
			errChan <- fmt.Errorf("client2 start failed: %w", err)
			cancel2()
		} else {
			errChan <- nil
			cancel2()
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
	type result struct {
		err    error
		client string
	}

	resultChan := make(chan result, 2)

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	go func() {
		err := dac.client1.WaitForSVID(waitCtx, spiffeID, timeout)
		resultChan <- result{err: err, client: "agent1"}
	}()

	go func() {
		err := dac.client2.WaitForSVID(waitCtx, spiffeID, timeout)
		resultChan <- result{err: err, client: "agent2"}
	}()

	var results []result
	timeoutChan := time.After(timeout + 30*time.Second)

	for i := 0; i < 2; i++ {
		select {
		case res := <-resultChan:
			results = append(results, res)
			// Return when first client succeeds
			if res.err == nil {
				dac.logger.Info("successfully waited for SVID",
					"client", res.client,
					"spiffe_id", spiffeID)
				return nil
			}
			dac.logger.Debug("client failed to provide SVID",
				"client", res.client,
				"spiffe_id", spiffeID,
				"error", res.err)
		case <-timeoutChan:
			dac.logger.Error("timeout waiting for SVID from clients",
				"spiffe_id", spiffeID,
				"timeout", timeout)
			return fmt.Errorf("timeout waiting for SVID %s", spiffeID)
		case <-ctx.Done():
			dac.logger.Debug("context cancelled while waiting for SVID",
				"spiffe_id", spiffeID)
			return ctx.Err()
		}
	}

	dac.logger.Error("no client could provide SVID",
		"spiffe_id", spiffeID,
		"client_count", len(results))
	return fmt.Errorf("no client could provide SVID for %s", spiffeID)
}

// WaitForTrustBundle waits for trust bundle from either client
func (dac *DualAgentClient) WaitForTrustBundle(ctx context.Context, timeout time.Duration) error {
	type result struct {
		err    error
		client string
	}

	resultChan := make(chan result, 2)

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	go func() {
		err := dac.client1.WaitForTrustBundle(waitCtx, timeout)
		resultChan <- result{err: err, client: "agent1"}
	}()

	go func() {
		err := dac.client2.WaitForTrustBundle(waitCtx, timeout)
		resultChan <- result{err: err, client: "agent2"}
	}()

	var results []result
	timeoutChan := time.After(timeout + 30*time.Second)

	for i := 0; i < 2; i++ {
		select {
		case res := <-resultChan:
			results = append(results, res)
			if res.err == nil {
				dac.logger.Debug("successfully waited for trust bundle",
					"client", res.client)
				return nil
			}
			dac.logger.Debug("client failed to provide trust bundle",
				"client", res.client,
				"error", res.err)
		case <-timeoutChan:
			dac.logger.Error("timeout waiting for trust bundle from clients",
				"timeout", timeout)
			return fmt.Errorf("timeout waiting for trust bundle")
		case <-ctx.Done():
			dac.logger.Debug("context cancelled while waiting for trust bundle")
			return ctx.Err()
		}
	}

	dac.logger.Error("no client could provide trust bundle",
		"client_count", len(results))
	return fmt.Errorf("no client could provide trust bundle")
}

// GetCACertificates returns CA certificates from first available client
func (dac *DualAgentClient) GetCACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	type result struct {
		certs  []*x509.Certificate
		err    error
		client string
	}

	resultChan := make(chan result, 2)

	fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	go func() {
		opCtx, opCancel := context.WithTimeout(fetchCtx, 3*time.Second)
		defer opCancel()

		done := make(chan struct{})
		var certs []*x509.Certificate
		var err error

		go func() {
			certs, err = dac.client1.GetCACertificates(opCtx)
			close(done)
		}()

		select {
		case <-done:
			resultChan <- result{certs: certs, err: err, client: "agent1"}
		case <-opCtx.Done():
			resultChan <- result{err: fmt.Errorf("agent1 timeout: %w", opCtx.Err()), client: "agent1"}
		}
	}()

	go func() {
		opCtx, opCancel := context.WithTimeout(fetchCtx, 3*time.Second)
		defer opCancel()

		done := make(chan struct{})
		var certs []*x509.Certificate
		var err error

		go func() {
			certs, err = dac.client2.GetCACertificates(opCtx)
			close(done)
		}()

		select {
		case <-done:
			resultChan <- result{certs: certs, err: err, client: "agent2"}
		case <-opCtx.Done():
			resultChan <- result{err: fmt.Errorf("agent2 timeout: %w", opCtx.Err()), client: "agent2"}
		}
	}()

	var results []result
	timeout := time.After(5 * time.Second)

	for i := 0; i < 2; i++ {
		select {
		case res := <-resultChan:
			results = append(results, res)
			if res.err == nil && res.certs != nil && len(res.certs) > 0 {
				dac.logger.Debug("successfully got CA certificates",
					"client", res.client,
					"cert_count", len(res.certs))
				return res.certs, nil
			}
			dac.logger.Debug("client failed to provide CA certificates",
				"client", res.client,
				"error", res.err)
		case <-timeout:
			dac.logger.Error("timeout waiting for CA certificates from clients")
			break
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Check if any client returned certificates
	for _, res := range results {
		if res.certs != nil && len(res.certs) > 0 {
			dac.logger.Warn("returning CA certificates despite errors",
				"client", res.client,
				"cert_count", len(res.certs))
			return res.certs, nil
		}
	}

	return nil, fmt.Errorf("failed to get CA certificates from any client")
}

// GetCertificateForIdentity returns certificate from first available client
func (dac *DualAgentClient) GetCertificateForIdentity(spiffeID string) (*tls.Certificate, error) {
	type result struct {
		cert   *tls.Certificate
		err    error
		client string
	}

	resultChan := make(chan result, 2)

	// Create a context with timeout for each operation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try both clients concurrently with timeout
	go func() {
		opCtx, opCancel := context.WithTimeout(ctx, 3*time.Second)
		defer opCancel()

		done := make(chan struct{})
		var cert *tls.Certificate
		var err error

		go func() {
			cert, err = dac.client1.GetCertificateForIdentity(spiffeID)
			close(done)
		}()

		select {
		case <-done:
			resultChan <- result{cert: cert, err: err, client: "agent1"}
		case <-opCtx.Done():
			resultChan <- result{err: fmt.Errorf("agent1 timeout: %w", opCtx.Err()), client: "agent1"}
		}
	}()

	go func() {
		opCtx, opCancel := context.WithTimeout(ctx, 3*time.Second)
		defer opCancel()

		done := make(chan struct{})
		var cert *tls.Certificate
		var err error

		go func() {
			cert, err = dac.client2.GetCertificateForIdentity(spiffeID)
			close(done)
		}()

		select {
		case <-done:
			resultChan <- result{cert: cert, err: err, client: "agent2"}
		case <-opCtx.Done():
			resultChan <- result{err: fmt.Errorf("agent2 timeout: %w", opCtx.Err()), client: "agent2"}
		}
	}()

	var results []result
	timeout := time.After(6 * time.Second)

	for i := 0; i < 2; i++ {
		select {
		case res := <-resultChan:
			results = append(results, res)
			// Return first successful response
			if res.err == nil && res.cert != nil {
				dac.logger.Debug("successfully got certificate",
					"client", res.client,
					"spiffe_id", spiffeID)
				return res.cert, nil
			}
			dac.logger.Debug("client failed to provide certificate",
				"client", res.client,
				"spiffe_id", spiffeID,
				"error", res.err)
		case <-timeout:
			dac.logger.Error("timeout waiting for certificate from clients",
				"spiffe_id", spiffeID)
			break
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Check if any client returned a certificate despite errors
	for _, res := range results {
		if res.cert != nil {
			dac.logger.Warn("returning certificate despite errors",
				"client", res.client,
				"spiffe_id", spiffeID)
			return res.cert, nil
		}
	}

	return nil, fmt.Errorf("failed to get certificate from any client for %s", spiffeID)
}

// FetchJWTSVID fetches JWT SVID from both clients concurrently
func (dac *DualAgentClient) FetchJWTSVID(ctx context.Context, spiffeID string, audiences []string) (string, error) {
	type result struct {
		token  string
		err    error
		client string
	}

	resultChan := make(chan result, 2)

	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	go func() {
		token, err := dac.client1.FetchJWTSVID(fetchCtx, spiffeID, audiences)
		resultChan <- result{token: token, err: err, client: "agent1"}
	}()

	go func() {
		token, err := dac.client2.FetchJWTSVID(fetchCtx, spiffeID, audiences)
		resultChan <- result{token: token, err: err, client: "agent2"}
	}()

	var results []result
	timeout := time.After(15 * time.Second)

	for i := 0; i < 2; i++ {
		select {
		case res := <-resultChan:
			results = append(results, res)
			// Return first successful response
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
		case <-timeout:
			dac.logger.Error("timeout waiting for JWT SVID from clients")
			break
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	// Check if any client returned a token
	for _, res := range results {
		if res.token != "" {
			dac.logger.Warn("returning token despite errors",
				"client", res.client,
				"spiffe_id", spiffeID)
			return res.token, nil
		}
	}

	return "", fmt.Errorf("failed to fetch JWT SVID from any client")
}

// GetTrustBundle returns trust bundle from first available client
func (dac *DualAgentClient) GetTrustBundle() (*x509.CertPool, error) {
	type result struct {
		bundle *x509.CertPool
		err    error
		client string
	}

	resultChan := make(chan result, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		done := make(chan struct{})
		var bundle *x509.CertPool
		var err error

		go func() {
			bundle, err = dac.client1.GetTrustBundle()
			close(done)
		}()

		select {
		case <-done:
			resultChan <- result{bundle: bundle, err: err, client: "agent1"}
		case <-ctx.Done():
			resultChan <- result{err: fmt.Errorf("agent1 timeout: %w", ctx.Err()), client: "agent1"}
		}
	}()

	go func() {
		done := make(chan struct{})
		var bundle *x509.CertPool
		var err error

		go func() {
			bundle, err = dac.client2.GetTrustBundle()
			close(done)
		}()

		select {
		case <-done:
			resultChan <- result{bundle: bundle, err: err, client: "agent2"}
		case <-ctx.Done():
			resultChan <- result{err: fmt.Errorf("agent2 timeout: %w", ctx.Err()), client: "agent2"}
		}
	}()

	var results []result
	timeout := time.After(5 * time.Second)

	for i := 0; i < 2; i++ {
		select {
		case res := <-resultChan:
			results = append(results, res)
			// Return first successful response
			if res.err == nil && res.bundle != nil {
				dac.logger.Debug("successfully got trust bundle",
					"client", res.client)
				return res.bundle, nil
			}
			dac.logger.Debug("client failed to provide trust bundle",
				"client", res.client,
				"error", res.err)
		case <-timeout:
			dac.logger.Error("timeout waiting for trust bundle from clients")
			break
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Check if any client returned a bundle
	for _, res := range results {
		if res.bundle != nil {
			dac.logger.Warn("returning trust bundle despite errors",
				"client", res.client)
			return res.bundle, nil
		}
	}

	return nil, fmt.Errorf("failed to get trust bundle from any client")
}

func (dac *DualAgentClient) GetBundlesByDomain(ctx context.Context) (map[string][]*x509.Certificate, error) {
	// Try both clients, return first success
	type result struct {
		bundles map[string][]*x509.Certificate
		err     error
		client  string
	}

	resultChan := make(chan result, 2)
	fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	go func() {
		bundles, err := dac.client1.GetBundlesByDomain(fetchCtx)
		resultChan <- result{bundles: bundles, err: err, client: "agent1"}
	}()

	go func() {
		bundles, err := dac.client2.GetBundlesByDomain(fetchCtx)
		resultChan <- result{bundles: bundles, err: err, client: "agent2"}
	}()

	// Return first successful response
	for i := 0; i < 2; i++ {
		select {
		case res := <-resultChan:
			if res.err == nil && res.bundles != nil {
				return res.bundles, nil
			}
		case <-fetchCtx.Done():
			return nil, fmt.Errorf("timeout getting bundles by domain")
		}
	}

	return nil, fmt.Errorf("failed to get bundles from any client")
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
