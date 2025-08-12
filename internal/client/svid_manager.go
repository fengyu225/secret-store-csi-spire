package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	delegatedapi "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
)

type svidManager struct {
	logger hclog.Logger

	store       map[string]*delegatedapi.X509SVIDWithKey
	parsedCerts map[string][]*x509.Certificate
	mu          sync.RWMutex

	waiters      map[string]chan struct{}
	waitersMutex sync.Mutex
}

func newSVIDManager(logger hclog.Logger) *svidManager {
	return &svidManager{
		logger:      logger,
		store:       make(map[string]*delegatedapi.X509SVIDWithKey),
		parsedCerts: make(map[string][]*x509.Certificate),
		waiters:     make(map[string]chan struct{}),
	}
}

func (sm *svidManager) waitForSVID(ctx context.Context, spiffeID string, timeout time.Duration) error {
	sm.logger.Debug("waiting for X509 SVID", "spiffe_id", spiffeID, "timeout", timeout)

	sm.mu.RLock()
	if _, exists := sm.store[spiffeID]; exists {
		sm.mu.RUnlock()
		sm.logger.Debug("SVID already available", "spiffe_id", spiffeID)
		return nil
	}
	sm.mu.RUnlock()

	waitChan := sm.registerWaiter(spiffeID)
	defer sm.unregisterWaiter(spiffeID)

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-waitChan:
		sm.logger.Debug("SVID became available", "spiffe_id", spiffeID)
		return nil
	case <-timeoutCtx.Done():
		return fmt.Errorf("timeout waiting for SVID %s", spiffeID)
	}
}

func (sm *svidManager) handleUpdate(svids []*delegatedapi.X509SVIDWithKey, trustDomain string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	newStore := make(map[string]*delegatedapi.X509SVIDWithKey)

	for _, svid := range svids {
		if svid.X509Svid.Id.TrustDomain != trustDomain {
			sm.logger.Debug("skipping X509-SVID update - trust domain mismatch",
				"expected", trustDomain,
				"received", svid.X509Svid.Id.TrustDomain,
			)
			continue
		}

		key := fmt.Sprintf("spiffe://%s%s", svid.X509Svid.Id.TrustDomain, svid.X509Svid.Id.Path)
		sm.logger.Debug("adding SVID to store", "spiffe_id", key)
		newStore[key] = svid

		if _, exists := sm.store[key]; !exists {
			sm.notifyWaiters(key)
		}
	}

	sm.store = newStore
	sm.logger.Info("X509-SVID store updated", "total", len(newStore))
}

func (sm *svidManager) getCertificate(spiffeID string) (*tls.Certificate, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	svid, ok := sm.store[spiffeID]
	if !ok {
		return nil, fmt.Errorf("no SPIFFE ID for %s", spiffeID)
	}

	if err := sm.validateExpiration(svid, spiffeID); err != nil {
		return nil, err
	}

	return sm.parseCertificate(svid, spiffeID)
}

func (sm *svidManager) validateExpiration(svid *delegatedapi.X509SVIDWithKey, spiffeID string) error {
	if svid.X509Svid == nil || svid.X509Svid.ExpiresAt <= 0 {
		return nil
	}

	expiresAt := time.Unix(svid.X509Svid.ExpiresAt, 0)
	now := time.Now()

	if now.After(expiresAt) {
		return fmt.Errorf("SVID for %s has expired", spiffeID)
	}

	timeUntilExpiry := expiresAt.Sub(now)
	if timeUntilExpiry < 5*time.Minute {
		sm.logger.Warn("SVID is close to expiry",
			"spiffe_id", spiffeID,
			"expires_in", timeUntilExpiry,
		)
	}

	return nil
}

func (sm *svidManager) parseCertificate(svid *delegatedapi.X509SVIDWithKey, spiffeID string) (*tls.Certificate, error) {
	if len(svid.X509Svid.CertChain) == 0 {
		return nil, fmt.Errorf("no certificate chain inside %s", spiffeID)
	}

	var leafCert *x509.Certificate
	for _, cert := range svid.X509Svid.CertChain {
		cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		if !cert.IsCA {
			leafCert = cert
			break
		}
	}

	if leafCert == nil {
		return nil, fmt.Errorf("no leaf certificate inside %s", spiffeID)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(svid.X509SvidKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key of %s: %w", spiffeID, err)
	}

	return &tls.Certificate{
		Certificate: svid.X509Svid.CertChain,
		PrivateKey:  privKey,
		Leaf:        leafCert,
	}, nil
}

func (sm *svidManager) registerWaiter(spiffeID string) chan struct{} {
	sm.waitersMutex.Lock()
	defer sm.waitersMutex.Unlock()

	waitChan := make(chan struct{})
	sm.waiters[spiffeID] = waitChan
	sm.logger.Debug("registered SVID waiter", "spiffe_id", spiffeID)
	return waitChan
}

func (sm *svidManager) unregisterWaiter(spiffeID string) {
	sm.waitersMutex.Lock()
	defer sm.waitersMutex.Unlock()
	delete(sm.waiters, spiffeID)
}

func (sm *svidManager) notifyWaiters(spiffeID string) {
	sm.waitersMutex.Lock()
	defer sm.waitersMutex.Unlock()

	if waitChan, exists := sm.waiters[spiffeID]; exists {
		close(waitChan)
		delete(sm.waiters, spiffeID)
		sm.logger.Debug("notified SVID waiter", "spiffe_id", spiffeID)
	}
}

func (sm *svidManager) size() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.store)
}
