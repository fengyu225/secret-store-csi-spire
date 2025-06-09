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
	SpiffeTrustDomain string
	Selectors         []*typesapi.Selector
	RotatedQueueSize  int
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

	client := &Client{
		config:       config,
		logger:       logger,
		svidStore:    map[string]*delegatedapi.X509SVIDWithKey{},
		parsedCerts:  map[string][]*x509.Certificate{},
		jwtSVIDCache: map[string]*jwtCacheEntry{},
	}

	return client, nil
}

func (c *Client) WaitForSVID(ctx context.Context, spiffeID string, timeout time.Duration) error {
	c.svidStoreMutex.RLock()
	if _, exists := c.svidStore[spiffeID]; exists {
		c.svidStoreMutex.RUnlock()
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

	// Wait
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-waitChan:
		return nil
	case <-timeoutCtx.Done():
		c.svidWaitersMutex.Lock()
		delete(c.svidWaiters, spiffeID)
		c.svidWaitersMutex.Unlock()
		return fmt.Errorf("timeout waiting for SVID %s", spiffeID)
	}
}

func (c *Client) WaitForTrustBundle(ctx context.Context, timeout time.Duration) error {
	c.parsedCertsMutex.RLock()
	if len(c.parsedCerts) > 0 {
		c.parsedCertsMutex.RUnlock()
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
		return nil
	case <-timeoutCtx.Done():
		return fmt.Errorf("timeout waiting for trust bundle")
	}
}

func (c *Client) Start(ctx context.Context) error {
	c.logger.Info("SPIRE Delegated Identity client is starting")

	listenCtx, cancel := context.WithCancel(context.Background())
	go c.listenForUpdates(listenCtx)

	c.cancelListenForUpdates = cancel

	return nil
}

func (c *Client) Stop() error {
	c.logger.Info("SPIRE Delegated Identity client is stopping")

	if c.cancelListenForUpdates != nil {
		c.cancelListenForUpdates()
	}

	if c.stream != nil {
		c.stream.CloseSend()
	}

	if c.trustStream != nil {
		c.trustStream.CloseSend()
	}

	return nil
}

func (c *Client) GetCACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	c.parsedCertsMutex.RLock()
	defer c.parsedCertsMutex.RUnlock()

	if len(c.parsedCerts) == 0 {
		return nil, errors.New("no certificates available in trust bundle")
	}

	var allCerts []*x509.Certificate
	for _, certs := range c.parsedCerts {
		allCerts = append(allCerts, certs...)
	}

	return allCerts, nil
}

func (c *Client) FetchJWTSVID(ctx context.Context, spiffeID string, audiences []string) (string, error) {
	if c.delegatedIdentityClient == nil {
		return "", errors.New("not connected to SPIRE Delegated Identity API")
	}

	cacheKey := c.createJWTCacheKey(spiffeID, audiences)

	c.jwtSVIDCacheMutex.RLock()
	cachedEntry, exists := c.jwtSVIDCache[cacheKey]
	c.jwtSVIDCacheMutex.RUnlock()

	now := time.Now()

	if exists && now.Before(cachedEntry.expiresAt) {
		shouldRefresh := now.Add(jwtRefreshBuffer).After(cachedEntry.expiresAt)

		if !shouldRefresh {
			c.logger.Debug("JWT-SVID cache hit (fresh)",
				"spiffeID", spiffeID,
				"audiences", audiences,
				"expiresAt", cachedEntry.expiresAt)
			return cachedEntry.token, nil
		}

		c.logger.Debug("JWT-SVID needs refresh (within buffer)",
			"spiffeID", spiffeID,
			"audiences", audiences,
			"expiresAt", cachedEntry.expiresAt)

		resp, err := c.delegatedIdentityClient.FetchJWTSVIDs(ctx, &delegatedapi.FetchJWTSVIDsRequest{
			Selectors: c.config.Selectors,
			Audience:  audiences,
		})

		if err != nil {
			// Fetch failed but we still have a valid cached token
			c.logger.Warn("Failed to refresh JWT-SVID, using cached token",
				"spiffeID", spiffeID,
				"audiences", audiences,
				"error", err,
				"cachedTokenExpiresAt", cachedEntry.expiresAt)
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

			c.logger.Debug("JWT-SVID refreshed and cached",
				"spiffeID", spiffeID,
				"audiences", audiences,
				"expiresAt", expiresAt)

			return svid.Token, nil
		}
	}

	c.logger.Debug("Fetching new JWT-SVID from SPIRE agent",
		"spiffeID", spiffeID,
		"audiences", audiences)

	resp, err := c.delegatedIdentityClient.FetchJWTSVIDs(ctx, &delegatedapi.FetchJWTSVIDsRequest{
		Selectors: c.config.Selectors,
		Audience:  audiences,
	})
	if err != nil {
		if exists {
			c.logger.Error("Failed to fetch JWT-SVID, returning expired cached token",
				"spiffeID", spiffeID,
				"audiences", audiences,
				"error", err,
				"expiredAt", cachedEntry.expiresAt)
			return cachedEntry.token, nil
		}
		return "", fmt.Errorf("failed to fetch JWT-SVID: %w", err)
	}

	if len(resp.Svids) == 0 {
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

	c.logger.Debug("JWT-SVID fetched and cached",
		"spiffeID", spiffeID,
		"audiences", audiences,
		"expiresAt", expiresAt)

	return svid.Token, nil
}

func (c *Client) createJWTCacheKey(spiffeID string, audiences []string) string {
	sortedAudiences := make([]string, len(audiences))
	copy(sortedAudiences, audiences)
	sort.Strings(sortedAudiences)

	return fmt.Sprintf("%s:%s", spiffeID, strings.Join(sortedAudiences, ","))
}

func (c *Client) listenForUpdates(ctx context.Context) {
	c.openStream(ctx)

	listenCtx, cancel := context.WithCancel(ctx)
	errChan := make(chan error)

	go c.listenForSVIDUpdates(listenCtx, errChan)
	go c.listenForBundleUpdates(listenCtx, errChan)

	for {
		select {
		case <-ctx.Done():
			cancel()
			return
		case err := <-errChan:
			c.logger.Error("Error in delegate stream, restarting", "error", err)

			time.Sleep(1 * time.Second)

			cancel()
			c.connectionAttempts++
			c.listenForUpdates(ctx)
			return
		}
	}
}

func (c *Client) openStream(ctx context.Context) {

	c.connectedMutex.Lock()
	c.connected = false
	c.connectedMutex.Unlock()

	for {
		c.logger.Info("Connecting to SPIRE Delegated Identity API")

		var err error
		c.stream, c.trustStream, err = c.initWatcher(ctx)
		if err != nil {
			c.logger.Warn("SPIRE Delegated Identity client failed to init watcher, retrying", "error", err)

			c.connectedMutex.Lock()
			c.connected = false
			c.lastConnectError = err
			c.connectedMutex.Unlock()

			time.Sleep(1 * time.Second)

			c.connectionAttempts++
			continue
		}

		c.connectedMutex.Lock()
		c.connected = true
		c.lastConnectError = nil
		c.connectedMutex.Unlock()

		break
	}
}

func (c *Client) initWatcher(ctx context.Context) (delegatedapi.DelegatedIdentity_SubscribeToX509SVIDsClient,
	delegatedapi.DelegatedIdentity_SubscribeToX509BundlesClient, error) {

	if _, err := os.Stat(c.config.SpireSocketPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("SPIRE socket (%s) does not exist: %w", c.config.SpireSocketPath, err)
	}

	unixPath := fmt.Sprintf("unix://%s", c.config.SpireSocketPath)

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

	c.logger.Debug("Subscribing to delegated identity API", "socket", c.config.SpireSocketPath, "selectors", c.config.Selectors)

	ctx, _ = context.WithTimeout(context.Background(), 1*time.Minute)
	stream, err := client.SubscribeToX509SVIDs(ctx, &delegatedapi.SubscribeToX509SVIDsRequest{
		Selectors: c.config.Selectors,
	})
	if err != nil {
		c.logger.Warn("SPIRE Delegated Identity client failed to subscribe", "error", err)
		conn.Close()
		return nil, nil, fmt.Errorf("stream failed on %s: %w", unixPath, err)
	}

	trustStream, err := client.SubscribeToX509Bundles(ctx, &delegatedapi.SubscribeToX509BundlesRequest{})
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("stream for x509 bundle failed on %s: %w", unixPath, err)
	}

	return stream, trustStream, nil
}

func (c *Client) listenForSVIDUpdates(ctx context.Context, errorChan chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			resp, err := c.stream.Recv()
			if err != nil {
				errorChan <- err
				return
			}

			c.logger.Debug("SPIRE Delegated Identity client received SVID update: ", resp)
			c.logger.Debug("Received X509-SVID update", "count", len(resp.X509Svids))
			c.handleX509SVIDUpdate(resp.X509Svids)
		}
	}
}

func (c *Client) listenForBundleUpdates(ctx context.Context, errorChan chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			resp, err := c.trustStream.Recv()
			if err != nil {
				errorChan <- err
				return
			}

			c.logger.Debug("Received X509-Bundle update", "count", len(resp.CaCertificates))
			c.handleX509BundleUpdate(resp.CaCertificates)
		}
	}
}

func (c *Client) handleX509SVIDUpdate(svids []*delegatedapi.X509SVIDWithKey) {
	newSvidStore := map[string]*delegatedapi.X509SVIDWithKey{}

	c.svidStoreMutex.RLock()
	updatedKeys := []string{}
	deletedKeys := []string{}

	for _, svid := range svids {
		if svid.X509Svid.Id.TrustDomain != c.config.SpiffeTrustDomain {
			c.logger.Debug("Skipping X509-SVID update as it does not match our trust domain",
				"trustDomain", svid.X509Svid.Id.TrustDomain)
			c.svidStoreMutex.RUnlock()
			return
		}

		key := fmt.Sprintf("spiffe://%s%s", svid.X509Svid.Id.TrustDomain, svid.X509Svid.Id.Path)

		if _, exists := c.svidStore[key]; exists {
			old := c.svidStore[key]
			if old.X509Svid.ExpiresAt != svid.X509Svid.ExpiresAt || !equalCertChains(old.X509Svid.CertChain, svid.X509Svid.CertChain) {
				updatedKeys = append(updatedKeys, key)
			}
		} else {
			c.logger.Debug("Adding newly discovered X509-SVID", "spiffeID", key)
			// Notify any waiters for this new SVID
			c.svidWaitersMutex.Lock()
			if waitChan, exists := c.svidWaiters[key]; exists {
				close(waitChan)
				delete(c.svidWaiters, key)
			}
			c.svidWaitersMutex.Unlock()
		}
		newSvidStore[key] = svid
	}

	for key := range c.svidStore {
		if _, exists := newSvidStore[key]; !exists {
			deletedKeys = append(deletedKeys, key)
		}
	}

	c.svidStoreMutex.RUnlock()

	c.svidStoreMutex.Lock()
	c.svidStore = newSvidStore
	c.svidStoreMutex.Unlock()
}

func (c *Client) handleX509BundleUpdate(bundles map[string][]byte) {

	pool := x509.NewCertPool()

	c.parsedCertsMutex.Lock()
	defer c.parsedCertsMutex.Unlock()

	c.parsedCerts = make(map[string][]*x509.Certificate)

	for trustDomain, bundle := range bundles {
		c.logger.Debug("Processing trust domain cert bundle", "trustDomain", trustDomain)

		certs, err := x509.ParseCertificates(bundle)
		if err != nil {
			c.logger.Error("Failed to parse X.509 DER bundle",
				"trustDomain", trustDomain,
				"error", err)
			continue
		}

		c.parsedCerts[trustDomain] = certs

		for _, cert := range certs {
			pool.AddCert(cert)
		}
	}

	c.trustBundle = pool

	c.trustBundleOnce.Do(func() {
		c.trustBundleReady = make(chan struct{})
	})
	select {
	case <-c.trustBundleReady:
		// Already closed
	default:
		close(c.trustBundleReady)
	}
}

func (c *Client) GetTrustBundle() (*x509.CertPool, error) {
	if c.trustBundle == nil {
		return nil, errors.New("trust bundle not yet available")
	}
	return c.trustBundle, nil
}

func (c *Client) GetCertificateForIdentity(spiffeID string) (*tls.Certificate, error) {
	c.svidStoreMutex.RLock()
	svid, ok := c.svidStore[spiffeID]
	c.svidStoreMutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no SPIFFE ID for %s", spiffeID)
	}

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

func (c *Client) Status() (bool, string) {
	c.connectedMutex.RLock()
	defer c.connectedMutex.RUnlock()

	if !c.connected {
		msg := "Not connected to SPIRE server"
		if c.lastConnectError != nil {
			msg = fmt.Sprintf("Cannot connect to SPIRE server: %q", c.lastConnectError)
		}
		return false, msg
	}

	return true, "Connected to SPIRE server"
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
