package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
)

type trustBundleManager struct {
	logger hclog.Logger

	trustBundle *x509.CertPool
	parsedCerts map[string][]*x509.Certificate
	mu          sync.RWMutex

	ready     chan struct{}
	readyOnce sync.Once
}

func newTrustBundleManager(logger hclog.Logger) *trustBundleManager {
	return &trustBundleManager{
		logger:      logger,
		parsedCerts: make(map[string][]*x509.Certificate),
	}
}

func (tbm *trustBundleManager) waitForBundle(ctx context.Context, timeout time.Duration) error {
	tbm.logger.Debug("waiting for trust bundle", "timeout", timeout)

	tbm.mu.RLock()
	if len(tbm.parsedCerts) > 0 {
		tbm.mu.RUnlock()
		tbm.logger.Debug("trust bundle already available")
		return nil
	}
	tbm.mu.RUnlock()

	tbm.readyOnce.Do(func() {
		tbm.ready = make(chan struct{})
	})

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-tbm.ready:
		tbm.logger.Debug("trust bundle became available")
		return nil
	case <-timeoutCtx.Done():
		tbm.logger.Error("timeout waiting for trust bundle", "timeout", timeout)
		return fmt.Errorf("timeout waiting for trust bundle")
	}
}

func (tbm *trustBundleManager) handleUpdate(bundles map[string][]byte) {
	pool := x509.NewCertPool()

	tbm.mu.Lock()
	defer tbm.mu.Unlock()

	oldCertCount := 0
	for _, certs := range tbm.parsedCerts {
		oldCertCount += len(certs)
	}

	tbm.parsedCerts = make(map[string][]*x509.Certificate)
	newCertCount := 0

	for trustDomain, bundle := range bundles {
		tbm.logger.Debug("processing trust domain bundle",
			"trust_domain", trustDomain,
			"bundle_size", len(bundle),
		)

		certs, err := x509.ParseCertificates(bundle)
		if err != nil {
			tbm.logger.Error("failed to parse X.509 DER bundle",
				"trust_domain", trustDomain,
				"error", err,
			)
			continue
		}

		tbm.parsedCerts[trustDomain] = certs
		newCertCount += len(certs)

		for _, cert := range certs {
			pool.AddCert(cert)
			tbm.logger.Trace("added certificate to trust bundle",
				"trust_domain", trustDomain,
				"subject", cert.Subject,
				"not_after", cert.NotAfter,
			)
		}
	}

	tbm.trustBundle = pool

	tbm.logger.Info("trust bundle updated",
		"trust_domains", len(bundles),
		"old_cert_count", oldCertCount,
		"new_cert_count", newCertCount,
	)

	// Signal that trust bundle is ready
	tbm.readyOnce.Do(func() {
		tbm.ready = make(chan struct{})
	})

	select {
	case <-tbm.ready:
		// Already closed
	default:
		close(tbm.ready)
		tbm.logger.Debug("trust bundle ready signal sent")
	}
}

func (tbm *trustBundleManager) getCACertificates() ([]*x509.Certificate, error) {
	tbm.mu.RLock()
	defer tbm.mu.RUnlock()

	if len(tbm.parsedCerts) == 0 {
		tbm.logger.Warn("no certificates available in trust bundle")
		return nil, errors.New("no certificates available in trust bundle")
	}

	var allCerts []*x509.Certificate
	certCount := 0
	for trustDomain, certs := range tbm.parsedCerts {
		allCerts = append(allCerts, certs...)
		certCount += len(certs)
		tbm.logger.Trace("returning certificates from trust domain",
			"trust_domain", trustDomain,
			"cert_count", len(certs),
		)
	}

	tbm.logger.Debug("returning CA certificates",
		"total_count", certCount,
		"trust_domain_count", len(tbm.parsedCerts),
	)

	return allCerts, nil
}

func (tbm *trustBundleManager) getTrustBundle() (*x509.CertPool, error) {
	tbm.mu.RLock()
	defer tbm.mu.RUnlock()

	if tbm.trustBundle == nil {
		tbm.logger.Warn("trust bundle requested but not yet available")
		return nil, errors.New("trust bundle not yet available")
	}
	return tbm.trustBundle, nil
}
