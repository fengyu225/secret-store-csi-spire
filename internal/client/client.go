package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	delegatedapi "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	typesapi "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"spire-csi-provider/internal/metrics"
)

const (
	// Start refreshing JWT SVIDs 1 hour before expiration
	jwtRefreshBuffer = 1 * time.Hour
)

type CertificateRotationEvent struct {
	Identity string
	Deleted  bool
}

type Config struct {
	SpireSocketPath   string
	SpireSocketPath2  string
	SpiffeTrustDomain string
	Selectors         []*typesapi.Selector
	RotatedQueueSize  int
	PodContext        metrics.PodContext
}

type jwtCacheEntry struct {
	token     string
	expiresAt time.Time
	audiences []string
}

type Client struct {
	config Config
	logger hclog.Logger

	delegatedIdentityClient delegatedapi.DelegatedIdentityClient

	connectionAttempts int

	stream      delegatedapi.DelegatedIdentity_SubscribeToX509SVIDsClient
	trustStream delegatedapi.DelegatedIdentity_SubscribeToX509BundlesClient

	svidStore      map[string]*delegatedapi.X509SVIDWithKey
	svidStoreMutex sync.RWMutex
	trustBundle    *x509.CertPool

	parsedCertsMutex sync.RWMutex
	parsedCerts      map[string][]*x509.Certificate

	cancelListenForUpdates context.CancelFunc

	connected        bool
	lastConnectError error
	connectedMutex   sync.RWMutex

	svidWaiters      map[string]chan struct{}
	svidWaitersMutex sync.Mutex

	trustBundleReady chan struct{}
	trustBundleOnce  sync.Once

	jwtSVIDCache      map[string]*jwtCacheEntry
	jwtSVIDCacheMutex sync.RWMutex

	podContext metrics.PodContext
}

func New(logger hclog.Logger, config Config) (*Client, error) {
	if config.SpireSocketPath == "" {
		return nil, errors.New("SPIRE socket path not specified")
	}

	if config.SpiffeTrustDomain == "" {
		return nil, errors.New("SPIRE trust domain not specified")
	}

	if config.RotatedQueueSize <= 0 {
		config.RotatedQueueSize = 1024
	}

	logger.Info("creating SPIRE client",
		"socket_path", config.SpireSocketPath,
		"trust_domain", config.SpiffeTrustDomain,
	)

	client := &Client{
		config:       config,
		logger:       logger,
		svidStore:    map[string]*delegatedapi.X509SVIDWithKey{},
		parsedCerts:  map[string][]*x509.Certificate{},
		jwtSVIDCache: map[string]*jwtCacheEntry{},
		podContext:   config.PodContext,
	}

	return client, nil
}

func (c *Client) WaitForSVID(ctx context.Context, spiffeID string, timeout time.Duration) error {
	c.logger.Debug("waiting for SVID",
		"spiffe_id", spiffeID,
		"timeout", timeout,
	)

	c.svidStoreMutex.RLock()
	if _, exists := c.svidStore[spiffeID]; exists {
		c.svidStoreMutex.RUnlock()
		c.logger.Debug("SVID already available", "spiffe_id", spiffeID)
		return nil
	}
	c.svidStoreMutex.RUnlock()

	// Register waiter
	c.svidWaitersMutex.Lock()
	if c.svidWaiters == nil {
		c.svidWaiters = make(map[string]chan struct{})
	}
	waitChan := make(chan struct{})
	c.svidWaiters[spiffeID] = waitChan
	c.svidWaitersMutex.Unlock()

	c.logger.Debug("registered SVID waiter", "spiffe_id", spiffeID)

	// Wait
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-waitChan:
		c.logger.Debug("SVID became available", "spiffe_id", spiffeID)
		return nil
	case <-timeoutCtx.Done():
		c.svidWaitersMutex.Lock()
		delete(c.svidWaiters, spiffeID)
		c.svidWaitersMutex.Unlock()
		c.logger.Error("timeout waiting for SVID",
			"spiffe_id", spiffeID,
			"timeout", timeout,
		)
		return fmt.Errorf("timeout waiting for SVID %s", spiffeID)
	}
}

func (c *Client) WaitForTrustBundle(ctx context.Context, timeout time.Duration) error {
	c.logger.Debug("waiting for trust bundle", "timeout", timeout)

	c.parsedCertsMutex.RLock()
	if len(c.parsedCerts) > 0 {
		c.parsedCertsMutex.RUnlock()
		c.logger.Debug("trust bundle already available")
		return nil
	}
	c.parsedCertsMutex.RUnlock()

	// Initialize channel once
	c.trustBundleOnce.Do(func() {
		c.trustBundleReady = make(chan struct{})
	})

	// Wait
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-c.trustBundleReady:
		c.logger.Debug("trust bundle became available")
		return nil
	case <-timeoutCtx.Done():
		c.logger.Error("timeout waiting for trust bundle", "timeout", timeout)
		return fmt.Errorf("timeout waiting for trust bundle")
	}
}

func (c *Client) Start(ctx context.Context) error {
	c.logger.Info("starting SPIRE Delegated Identity client")

	listenCtx, cancel := context.WithCancel(context.Background())
	go c.listenForUpdates(listenCtx)

	c.cancelListenForUpdates = cancel

	return nil
}

func (c *Client) Stop() error {
	c.logger.Info("stopping SPIRE Delegated Identity client")

	if c.cancelListenForUpdates != nil {
		c.cancelListenForUpdates()
	}

	if c.stream != nil {
		c.stream.CloseSend()
	}

	if c.trustStream != nil {
		c.trustStream.CloseSend()
	}

	metrics.UpdateSpireConnectionStatus(false, c.podContext)

	return nil
}

func (c *Client) GetCACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	c.parsedCertsMutex.RLock()
	defer c.parsedCertsMutex.RUnlock()

	if len(c.parsedCerts) == 0 {
		c.logger.Warn("no certificates available in trust bundle")
		return nil, errors.New("no certificates available in trust bundle")
	}

	var allCerts []*x509.Certificate
	certCount := 0
	for trustDomain, certs := range c.parsedCerts {
		allCerts = append(allCerts, certs...)
		certCount += len(certs)
		c.logger.Trace("returning certificates from trust domain",
			"trust_domain", trustDomain,
			"cert_count", len(certs),
		)
	}

	c.logger.Debug("returning CA certificates",
		"total_count", certCount,
		"trust_domain_count", len(c.parsedCerts),
	)

	return allCerts, nil
}

func (c *Client) FetchJWTSVID(ctx context.Context, spiffeID string, audiences []string) (string, error) {
	if c.delegatedIdentityClient == nil {
		c.logger.Error("not connected to SPIRE Delegated Identity API")
		return "", errors.New("not connected to SPIRE Delegated Identity API")
	}

	cacheKey := c.createJWTCacheKey(spiffeID, audiences)

	c.jwtSVIDCacheMutex.RLock()
	cachedEntry, exists := c.jwtSVIDCache[cacheKey]
	c.jwtSVIDCacheMutex.RUnlock()

	now := time.Now()

	if exists && now.Before(cachedEntry.expiresAt) {
		shouldRefresh := now.Add(jwtRefreshBuffer).After(cachedEntry.expiresAt)
		timeUntilExpiry := cachedEntry.expiresAt.Sub(now)

		if !shouldRefresh {
			c.logger.Debug("JWT-SVID cache hit",
				"spiffe_id", spiffeID,
				"audiences", audiences,
				"expires_at", cachedEntry.expiresAt,
				"time_until_expiry", timeUntilExpiry,
			)
			metrics.RecordJWTCacheHit(c.podContext)
			return cachedEntry.token, nil
		}

		c.logger.Debug("JWT-SVID needs refresh",
			"spiffe_id", spiffeID,
			"audiences", audiences,
			"expires_at", cachedEntry.expiresAt,
			"time_until_expiry", timeUntilExpiry,
		)

		resp, err := c.delegatedIdentityClient.FetchJWTSVIDs(ctx, &delegatedapi.FetchJWTSVIDsRequest{
			Selectors: c.config.Selectors,
			Audience:  audiences,
		})

		if err != nil {
			// Fetch failed but we still have a valid cached token
			c.logger.Warn("failed to refresh JWT-SVID, using cached token",
				"spiffe_id", spiffeID,
				"audiences", audiences,
				"error", err,
				"cached_token_expires_at", cachedEntry.expiresAt,
			)
			return cachedEntry.token, nil
		}

		if len(resp.Svids) > 0 {
			svid := resp.Svids[0]
			expiresAt := time.Unix(svid.ExpiresAt, 0)

			c.jwtSVIDCacheMutex.Lock()
			c.jwtSVIDCache[cacheKey] = &jwtCacheEntry{
				token:     svid.Token,
				expiresAt: expiresAt,
				audiences: audiences,
			}
			c.jwtSVIDCacheMutex.Unlock()

			c.logger.Info("JWT-SVID refreshed and cached",
				"spiffe_id", spiffeID,
				"audiences", audiences,
				"expires_at", expiresAt,
			)

			metrics.RecordSpireSVIDReceived("jwt", c.podContext)
			c.updateCacheMetrics()

			return svid.Token, nil
		}
	}

	c.logger.Info("fetching new JWT-SVID from SPIRE agent",
		"spiffe_id", spiffeID,
		"audiences", audiences,
	)
	metrics.RecordJWTCacheMiss(c.podContext)

	resp, err := c.delegatedIdentityClient.FetchJWTSVIDs(ctx, &delegatedapi.FetchJWTSVIDsRequest{
		Selectors: c.config.Selectors,
		Audience:  audiences,
	})
	if err != nil {
		if exists {
			c.logger.Error("failed to fetch JWT-SVID, returning expired cached token",
				"spiffe_id", spiffeID,
				"audiences", audiences,
				"error", err,
				"expired_at", cachedEntry.expiresAt,
			)
			return cachedEntry.token, nil
		}
		c.logger.Error("failed to fetch JWT-SVID",
			"spiffe_id", spiffeID,
			"audiences", audiences,
			"error", err,
		)
		return "", fmt.Errorf("failed to fetch JWT-SVID: %w", err)
	}

	if len(resp.Svids) == 0 {
		c.logger.Error("no JWT-SVIDs returned",
			"spiffe_id", spiffeID,
			"audiences", audiences,
		)
		return "", errors.New("no JWT-SVIDs returned")
	}

	svid := resp.Svids[0]
	expiresAt := time.Unix(svid.ExpiresAt, 0)

	c.jwtSVIDCacheMutex.Lock()
	c.jwtSVIDCache[cacheKey] = &jwtCacheEntry{
		token:     svid.Token,
		expiresAt: expiresAt,
		audiences: audiences,
	}
	c.jwtSVIDCacheMutex.Unlock()

	c.logger.Info("JWT-SVID fetched and cached",
		"spiffe_id", spiffeID,
		"audiences", audiences,
		"expires_at", expiresAt,
	)

	metrics.RecordSpireSVIDReceived("jwt", c.podContext)
	c.updateCacheMetrics()

	return svid.Token, nil
}

func (c *Client) createJWTCacheKey(spiffeID string, audiences []string) string {
	sortedAudiences := make([]string, len(audiences))
	copy(sortedAudiences, audiences)
	sort.Strings(sortedAudiences)

	return fmt.Sprintf("%s:%s", spiffeID, strings.Join(sortedAudiences, ","))
}

func (c *Client) listenForUpdates(ctx context.Context) {
	c.logger.Debug("starting update listener")
	c.openStream(ctx)

	listenCtx, cancel := context.WithCancel(ctx)
	errChan := make(chan error)

	go c.listenForSVIDUpdates(listenCtx, errChan)
	go c.listenForBundleUpdates(listenCtx, errChan)

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("update listener context cancelled")
			cancel()
			return
		case err := <-errChan:
			c.logger.Error("error in delegate stream, restarting",
				"error", err,
				"connection_attempts", c.connectionAttempts,
			)

			time.Sleep(1 * time.Second)

			cancel()
			c.connectionAttempts++
			go c.listenForUpdates(ctx)
			return
		}
	}
}

func (c *Client) openStream(ctx context.Context) {
	c.logger.Info("opening SPIRE stream connection")

	c.connectedMutex.Lock()
	c.connected = false
	c.connectedMutex.Unlock()

	metrics.UpdateSpireConnectionStatus(false, c.podContext)

	for {
		c.logger.Info("connecting to SPIRE Delegated Identity API",
			"attempt", c.connectionAttempts+1,
			"socket", c.config.SpireSocketPath,
		)

		var err error
		c.stream, c.trustStream, err = c.initWatcher(ctx)
		if err != nil {
			c.logger.Warn("SPIRE Delegated Identity client failed to init watcher",
				"error", err,
				"attempt", c.connectionAttempts+1,
			)

			c.connectedMutex.Lock()
			c.connected = false
			c.lastConnectError = err
			c.connectedMutex.Unlock()

			metrics.RecordSpireConnectionAttempt(c.podContext)
			time.Sleep(1 * time.Second)

			c.connectionAttempts++
			continue
		}

		c.connectedMutex.Lock()
		c.connected = true
		c.lastConnectError = nil
		c.connectedMutex.Unlock()

		metrics.UpdateSpireConnectionStatus(true, c.podContext)
		metrics.RecordSpireConnectionAttempt(c.podContext)

		c.logger.Info("successfully connected to SPIRE Delegated Identity API")
		break
	}
}

func (c *Client) initWatcher(ctx context.Context) (delegatedapi.DelegatedIdentity_SubscribeToX509SVIDsClient,
	delegatedapi.DelegatedIdentity_SubscribeToX509BundlesClient, error) {

	if _, err := os.Stat(c.config.SpireSocketPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("SPIRE socket (%s) does not exist: %w", c.config.SpireSocketPath, err)
	}

	unixPath := fmt.Sprintf("unix://%s", c.config.SpireSocketPath)

	c.logger.Debug("creating gRPC connection", "path", unixPath)

	conn, err := grpc.NewClient(unixPath, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(20*1024*1024),
			grpc.MaxCallSendMsgSize(20*1024*1024)))

	if err != nil {
		return nil, nil, fmt.Errorf("grpc.Dial() failed on %s: %w", unixPath, err)
	}

	client := delegatedapi.NewDelegatedIdentityClient(conn)
	c.delegatedIdentityClient = client

	c.logger.Debug("SPIRE Delegated Identity client successfully initialized")

	for i, selector := range c.config.Selectors {
		c.logger.Debug("subscribing with selector",
			"index", i,
			"type", selector.Type,
			"value", selector.Value,
		)
	}

	stream, err := client.SubscribeToX509SVIDs(ctx, &delegatedapi.SubscribeToX509SVIDsRequest{
		Selectors: c.config.Selectors,
	})
	if err != nil {
		c.logger.Warn("SPIRE Delegated Identity client failed to subscribe to X509 SVIDs",
			"error", err,
		)
		conn.Close()
		return nil, nil, fmt.Errorf("stream failed on %s: %w", unixPath, err)
	}

	trustStream, err := client.SubscribeToX509Bundles(ctx, &delegatedapi.SubscribeToX509BundlesRequest{})
	if err != nil {
		c.logger.Warn("SPIRE Delegated Identity client failed to subscribe to X509 bundles",
			"error", err,
		)
		conn.Close()
		return nil, nil, fmt.Errorf("stream for x509 bundle failed on %s: %w", unixPath, err)
	}

	return stream, trustStream, nil
}

func (c *Client) listenForSVIDUpdates(ctx context.Context, errorChan chan<- error) {
	c.logger.Debug("starting SVID update listener")
	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("SVID update listener stopped")
			return
		default:
			resp, err := c.stream.Recv()
			if err != nil {
				c.logger.Error("error receiving SVID update", "error", err)
				errorChan <- err
				return
			}

			c.logger.Info("received X509-SVID update",
				"svid_count", len(resp.X509Svids),
			)
			c.handleX509SVIDUpdate(resp.X509Svids)
		}
	}
}

func (c *Client) listenForBundleUpdates(ctx context.Context, errorChan chan<- error) {
	c.logger.Debug("starting bundle update listener")
	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("bundle update listener stopped")
			return
		default:
			resp, err := c.trustStream.Recv()
			if err != nil {
				c.logger.Error("error receiving bundle update", "error", err)
				errorChan <- err
				return
			}

			c.logger.Info("received X509-Bundle update",
				"bundle_count", len(resp.CaCertificates),
			)
			c.handleX509BundleUpdate(resp.CaCertificates)
		}
	}
}

func (c *Client) handleX509SVIDUpdate(svids []*delegatedapi.X509SVIDWithKey) {
	newSvidStore := map[string]*delegatedapi.X509SVIDWithKey{}

	c.svidStoreMutex.RLock()
	updatedKeys := []string{}
	deletedKeys := []string{}
	newKeys := []string{}

	for _, svid := range svids {
		if svid.X509Svid.Id.TrustDomain != c.config.SpiffeTrustDomain {
			c.logger.Debug("skipping X509-SVID update - trust domain mismatch",
				"expected", c.config.SpiffeTrustDomain,
				"received", svid.X509Svid.Id.TrustDomain,
			)
			c.svidStoreMutex.RUnlock()
			return
		}

		key := fmt.Sprintf("spiffe://%s%s", svid.X509Svid.Id.TrustDomain, svid.X509Svid.Id.Path)

		if _, exists := c.svidStore[key]; exists {
			old := c.svidStore[key]
			if old.X509Svid.ExpiresAt != svid.X509Svid.ExpiresAt || !equalCertChains(old.X509Svid.CertChain, svid.X509Svid.CertChain) {
				updatedKeys = append(updatedKeys, key)
				c.logger.Debug("updating existing X509-SVID",
					"spiffe_id", key,
					"expires_at", time.Unix(svid.X509Svid.ExpiresAt, 0),
				)
			}
		} else {
			newKeys = append(newKeys, key)
			c.logger.Info("adding new X509-SVID",
				"spiffe_id", key,
				"expires_at", time.Unix(svid.X509Svid.ExpiresAt, 0),
			)
			// Notify any waiters for this new SVID
			c.svidWaitersMutex.Lock()
			if waitChan, exists := c.svidWaiters[key]; exists {
				close(waitChan)
				delete(c.svidWaiters, key)
				c.logger.Debug("notified SVID waiter", "spiffe_id", key)
			}
			c.svidWaitersMutex.Unlock()
			metrics.RecordSpireSVIDReceived("x509", c.podContext)
		}
		newSvidStore[key] = svid
	}

	for key := range c.svidStore {
		if _, exists := newSvidStore[key]; !exists {
			deletedKeys = append(deletedKeys, key)
			c.logger.Info("removing deleted X509-SVID", "spiffe_id", key)
		}
	}

	c.svidStoreMutex.RUnlock()

	c.svidStoreMutex.Lock()
	c.svidStore = newSvidStore
	c.svidStoreMutex.Unlock()

	if len(newKeys) > 0 || len(updatedKeys) > 0 || len(deletedKeys) > 0 {
		c.logger.Info("X509-SVID store updated",
			"new", len(newKeys),
			"updated", len(updatedKeys),
			"deleted", len(deletedKeys),
			"total", len(newSvidStore),
		)
	}

	c.updateCacheMetrics()
}

func (c *Client) handleX509BundleUpdate(bundles map[string][]byte) {
	pool := x509.NewCertPool()

	c.parsedCertsMutex.Lock()
	defer c.parsedCertsMutex.Unlock()

	oldCertCount := 0
	for _, certs := range c.parsedCerts {
		oldCertCount += len(certs)
	}

	c.parsedCerts = make(map[string][]*x509.Certificate)
	newCertCount := 0

	for trustDomain, bundle := range bundles {
		c.logger.Debug("processing trust domain bundle",
			"trust_domain", trustDomain,
			"bundle_size", len(bundle),
		)

		certs, err := x509.ParseCertificates(bundle)
		if err != nil {
			c.logger.Error("failed to parse X.509 DER bundle",
				"trust_domain", trustDomain,
				"error", err,
			)
			continue
		}

		c.parsedCerts[trustDomain] = certs
		newCertCount += len(certs)

		for _, cert := range certs {
			pool.AddCert(cert)
			c.logger.Trace("added certificate to trust bundle",
				"trust_domain", trustDomain,
				"subject", cert.Subject,
				"not_after", cert.NotAfter,
			)
		}
	}

	c.trustBundle = pool

	c.logger.Info("trust bundle updated",
		"trust_domains", len(bundles),
		"old_cert_count", oldCertCount,
		"new_cert_count", newCertCount,
	)

	// Signal that trust bundle is ready
	c.trustBundleOnce.Do(func() {
		c.trustBundleReady = make(chan struct{})
	})
	select {
	case <-c.trustBundleReady:
		// Already closed
	default:
		close(c.trustBundleReady)
		c.logger.Debug("trust bundle ready signal sent")
	}

	metrics.RecordSpireBundleUpdate(c.podContext)
}

func (c *Client) GetTrustBundle() (*x509.CertPool, error) {
	if c.trustBundle == nil {
		c.logger.Warn("trust bundle requested but not yet available")
		return nil, errors.New("trust bundle not yet available")
	}
	return c.trustBundle, nil
}

func (c *Client) GetCertificateForIdentity(spiffeID string) (*tls.Certificate, error) {
	c.logger.Debug("getting certificate for identity", "spiffe_id", spiffeID)

	c.svidStoreMutex.RLock()
	svid, ok := c.svidStore[spiffeID]
	c.svidStoreMutex.RUnlock()
	if !ok {
		c.logger.Error("no SVID found for identity", "spiffe_id", spiffeID)
		return nil, fmt.Errorf("no SPIFFE ID for %s", spiffeID)
	}

	if len(svid.X509Svid.CertChain) == 0 {
		c.logger.Error("empty certificate chain", "spiffe_id", spiffeID)
		return nil, fmt.Errorf("no certificate chain inside %s", spiffeID)
	}

	var leafCert *x509.Certificate
	for _, cert := range svid.X509Svid.CertChain {
		cert, err := x509.ParseCertificate(cert)
		if err != nil {
			c.logger.Error("failed to parse certificate",
				"spiffe_id", spiffeID,
				"error", err,
			)
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		if !cert.IsCA {
			leafCert = cert
			break
		}
	}
	if leafCert == nil {
		c.logger.Error("no leaf certificate found", "spiffe_id", spiffeID)
		return nil, fmt.Errorf("no leaf certificate inside %s", spiffeID)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(svid.X509SvidKey)
	if err != nil {
		c.logger.Error("failed to parse private key",
			"spiffe_id", spiffeID,
			"error", err,
		)
		return nil, fmt.Errorf("failed to parse private key of %s: %w", spiffeID, err)
	}

	c.logger.Debug("successfully retrieved certificate",
		"spiffe_id", spiffeID,
		"not_after", leafCert.NotAfter,
	)

	return &tls.Certificate{
		Certificate: svid.X509Svid.CertChain,
		PrivateKey:  privKey,
		Leaf:        leafCert,
	}, nil
}

func (c *Client) Status() (bool, string) {
	c.connectedMutex.RLock()
	defer c.connectedMutex.RUnlock()

	if !c.connected {
		msg := "Not connected to SPIRE server"
		if c.lastConnectError != nil {
			msg = fmt.Sprintf("Cannot connect to SPIRE server: %q", c.lastConnectError)
		}
		c.logger.Debug("connection status check", "connected", false, "message", msg)
		return false, msg
	}

	c.logger.Trace("connection status check", "connected", true)
	return true, "Connected to SPIRE server"
}

func (c *Client) updateCacheMetrics() {
	c.jwtSVIDCacheMutex.RLock()
	jwtCacheSize := len(c.jwtSVIDCache)
	c.jwtSVIDCacheMutex.RUnlock()

	c.svidStoreMutex.RLock()
	svidCacheSize := len(c.svidStore)
	c.svidStoreMutex.RUnlock()

	metrics.UpdateCacheSizes(jwtCacheSize, svidCacheSize, c.podContext)
}

func equalCertChains(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
