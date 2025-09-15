package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"spire-csi-provider/internal/metrics"

	"github.com/hashicorp/go-hclog"
	delegatedapi "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	typesapi "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

const (
	jwtRefreshBuffer = 1 * time.Hour
)

// Config contains all configuration for the client
type Config struct {
	SpireSocketPath   string
	SpireSocketPath2  string
	SpiffeTrustDomain string
	Selectors         []*typesapi.Selector
	RotatedQueueSize  int
	PodContext        metrics.PodContext
	AgentID           string
}

type Client struct {
	config Config
	logger hclog.Logger

	conn *connectionManager

	svidManager *svidManager

	bundleManager *trustBundleManager

	jwtCache *jwtCacheManager

	streamManager *streamManager

	podContext metrics.PodContext
}

func New(logger hclog.Logger, config Config) (*Client, error) {
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	logger.Info("creating SPIRE client",
		"socket_path", config.SpireSocketPath,
		"trust_domain", config.SpiffeTrustDomain,
	)

	client := &Client{
		config:     config,
		logger:     logger,
		podContext: config.PodContext,
	}

	client.conn = newConnectionManager(logger.Named("connection"), config)
	client.svidManager = newSVIDManager(logger.Named("svid"))
	client.bundleManager = newTrustBundleManager(logger.Named("bundle"))
	client.jwtCache = newJWTCacheManager(logger.Named("jwt-cache"))
	client.streamManager = newStreamManager(logger.Named("stream"), client)

	return client, nil
}

func (c *Client) Start(ctx context.Context) error {
	c.logger.Info("starting SPIRE Delegated Identity client")
	return c.streamManager.start(ctx)
}

func (c *Client) Stop() error {
	c.logger.Info("stopping SPIRE Delegated Identity client")

	c.streamManager.stop()

	if c.svidManager != nil {
		c.svidManager.stopCleanup()
	}

	c.conn.close()

	agentID := c.config.AgentID
	if agentID == "" {
		agentID = "agent"
	}
	metrics.UpdateSpireConnectionStatus(false, agentID, c.podContext.Namespace, c.podContext.ServiceAccount, c.podContext.PodUID)
	return nil
}

func (c *Client) Status() (bool, string) {
	return c.conn.getStatus()
}

func (c *Client) WaitForSVID(ctx context.Context, spiffeID string, timeout time.Duration) error {
	if err := c.ensureConnection(ctx); err != nil {
		return err
	}

	return c.svidManager.waitForSVID(ctx, spiffeID, timeout)
}

func (c *Client) WaitForTrustBundle(ctx context.Context, timeout time.Duration) error {
	if err := c.ensureConnection(ctx); err != nil {
		return err
	}

	return c.bundleManager.waitForBundle(ctx, timeout)
}

func (c *Client) GetCACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	if err := c.ensureConnection(ctx); err != nil {
		return nil, err
	}

	return c.bundleManager.getCACertificates()
}

func (c *Client) GetCertificateForIdentity(spiffeID string) (*tls.Certificate, error) {
	if err := c.ensureConnection(context.Background()); err != nil {
		return nil, err
	}

	return c.svidManager.getCertificate(spiffeID)
}

func (c *Client) FetchJWTSVID(ctx context.Context, spiffeID string, audiences []string) (string, error) {
	if err := c.ensureConnection(ctx); err != nil {
		return "", err
	}

	if token := c.jwtCache.get(spiffeID, audiences); token != "" {
		agentID := c.config.AgentID
		if agentID == "" {
			agentID = "agent"
		}
		metrics.RecordJWTCacheHit(agentID, c.podContext.Namespace, c.podContext.ServiceAccount, c.podContext.PodUID)
		return token, nil
	}

	agentID := c.config.AgentID
	if agentID == "" {
		agentID = "agent"
	}
	metrics.RecordJWTCacheMiss(agentID, c.podContext.Namespace, c.podContext.ServiceAccount, c.podContext.PodUID)

	token, expiresAt, err := c.fetchJWTSVIDFromAgent(ctx, audiences)
	if err != nil {
		return "", err
	}

	c.jwtCache.put(spiffeID, audiences, token, expiresAt)

	metrics.RecordSpireSVIDReceived(agentID, "jwt", c.podContext.Namespace, c.podContext.ServiceAccount, c.podContext.PodUID)
	c.updateCacheMetrics()

	return token, nil
}

func (c *Client) GetTrustBundle() (*x509.CertPool, error) {
	return c.bundleManager.getTrustBundle()
}

// fetchJWTSVIDFromAgent fetches a JWT SVID from the SPIRE agent
func (c *Client) fetchJWTSVIDFromAgent(ctx context.Context, audiences []string) (string, time.Time, error) {
	c.logger.Info("fetching JWT-SVID from SPIRE agent", "audiences", audiences)

	client := c.conn.getClient()
	if client == nil {
		return "", time.Time{}, errors.New("not connected to SPIRE Delegated Identity API")
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := client.FetchJWTSVIDs(fetchCtx, &delegatedapi.FetchJWTSVIDsRequest{
		Selectors: c.config.Selectors,
		Audience:  audiences,
	})

	if err != nil {
		if isConnectionError(err) {
			c.logger.Warn("connection error while fetching JWT-SVID, attempting reconnection",
				"error", err,
				"audiences", audiences,
			)

			if reconnectErr := c.streamManager.reconnect(context.Background()); reconnectErr == nil {
				client = c.conn.getClient()
				retryCtx, retryCancel := context.WithTimeout(ctx, 10*time.Second)
				defer retryCancel()

				resp, err = client.FetchJWTSVIDs(retryCtx, &delegatedapi.FetchJWTSVIDsRequest{
					Selectors: c.config.Selectors,
					Audience:  audiences,
				})
			}
		}

		if err != nil {
			c.logger.Error("failed to fetch JWT-SVID",
				"audiences", audiences,
				"error", err,
			)
			return "", time.Time{}, fmt.Errorf("failed to fetch JWT-SVID: %w", err)
		}
	}

	if len(resp.Svids) == 0 {
		c.logger.Error("no JWT-SVIDs returned", "audiences", audiences)
		return "", time.Time{}, errors.New("no JWT-SVIDs returned")
	}

	svid := resp.Svids[0]
	expiresAt := time.Unix(svid.ExpiresAt, 0)

	c.logger.Info("JWT-SVID fetched successfully",
		"audiences", audiences,
		"expires_at", expiresAt,
	)

	return svid.Token, expiresAt, nil
}

// ensureConnection ensures we have a healthy connection
func (c *Client) ensureConnection(ctx context.Context) error {
	if c.streamManager != nil && c.streamManager.isHealthy() {
		return nil
	}

	if c.streamManager != nil {
		return c.streamManager.ensureHealthy(ctx)
	}

	return fmt.Errorf("stream manager not initialized")
}

// updateCacheMetrics updates all cache-related metrics
func (c *Client) updateCacheMetrics() {
	jwtSize := c.jwtCache.size()
	svidSize := c.svidManager.size()
	agentID := c.config.AgentID
	if agentID == "" {
		agentID = "agent"
	}
	metrics.UpdateCacheSizes(agentID, c.podContext.Namespace, c.podContext.ServiceAccount, c.podContext.PodUID, jwtSize, svidSize)
}

func validateConfig(config *Config) error {
	if config.SpireSocketPath == "" {
		return errors.New("SPIRE socket path not specified")
	}
	if config.SpiffeTrustDomain == "" {
		return errors.New("SPIRE trust domain not specified")
	}
	if config.RotatedQueueSize <= 0 {
		config.RotatedQueueSize = 1024
	}
	return nil
}
