package client

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"spire-csi-provider/internal/metrics"

	"github.com/hashicorp/go-hclog"
	delegatedapi "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type streamManager struct {
	logger hclog.Logger
	client *Client

	svidStream  delegatedapi.DelegatedIdentity_SubscribeToX509SVIDsClient
	trustStream delegatedapi.DelegatedIdentity_SubscribeToX509BundlesClient
	streamMutex sync.RWMutex

	listenCtx  context.Context
	cancelFunc context.CancelFunc

	initialized      atomic.Bool
	reconnecting     bool
	reconnectBackoff time.Duration
	reconnectMutex   sync.Mutex

	streamsHealthy atomic.Bool
}

func newStreamManager(logger hclog.Logger, client *Client) *streamManager {
	return &streamManager{
		logger:           logger,
		client:           client,
		reconnectBackoff: 1 * time.Second,
	}
}

func (sm *streamManager) start(ctx context.Context) error {
	if sm.initialized.Load() {
		sm.logger.Debug("stream manager already initialized")
		return nil
	}

	sm.listenCtx, sm.cancelFunc = context.WithCancel(context.Background())

	if err := sm.initializeStreams(sm.listenCtx); err != nil {
		sm.logger.Error("failed to initialize streams", "error", err)
		return err
	}

	errChan := make(chan error, 2)
	go sm.listenForSVIDUpdates(sm.listenCtx, errChan)
	go sm.listenForBundleUpdates(sm.listenCtx, errChan)

	go sm.monitorErrors(sm.listenCtx, errChan)

	sm.initialized.Store(true)
	sm.streamsHealthy.Store(true)

	sm.logger.Info("stream manager started successfully")
	agentID := sm.client.config.AgentID
	if agentID == "" {
		agentID = "agent"
	}
	metrics.UpdateSpireConnectionStatus(true, agentID, sm.client.podContext.Namespace, sm.client.podContext.ServiceAccount, sm.client.podContext.PodUID)
	return nil
}

func (sm *streamManager) stop() {
	if !sm.initialized.Load() {
		return
	}

	sm.logger.Debug("stopping stream manager")

	// Cancel the context to stop all listeners
	if sm.cancelFunc != nil {
		sm.cancelFunc()
		time.Sleep(50 * time.Millisecond)
	}

	sm.streamMutex.Lock()
	defer sm.streamMutex.Unlock()

	if sm.svidStream != nil {
		sm.svidStream.CloseSend()
		sm.svidStream = nil
	}
	if sm.trustStream != nil {
		sm.trustStream.CloseSend()
		sm.trustStream = nil
	}

	sm.initialized.Store(false)
	sm.streamsHealthy.Store(false)
}

func (sm *streamManager) isHealthy() bool {
	return sm.initialized.Load() && sm.streamsHealthy.Load()
}

func (sm *streamManager) ensureHealthy(ctx context.Context) error {
	if sm.isHealthy() {
		return nil
	}

	sm.logger.Debug("streams not healthy, checking if reconnection needed")

	if !sm.initialized.Load() {
		return sm.start(ctx)
	}

	if !sm.streamsHealthy.Load() {
		return sm.reconnect(ctx)
	}

	return nil
}

func (sm *streamManager) reconnect(ctx context.Context) error {
	sm.reconnectMutex.Lock()
	defer sm.reconnectMutex.Unlock()

	if sm.streamsHealthy.Load() {
		sm.logger.Debug("streams already healthy, skipping reconnection")
		return nil
	}

	if sm.reconnecting {
		sm.logger.Debug("reconnection already in progress")
		return nil
	}

	sm.reconnecting = true
	defer func() { sm.reconnecting = false }()

	sm.logger.Info("reconnecting to SPIRE agent", "backoff", sm.reconnectBackoff)

	if sm.reconnectBackoff > 0 {
		select {
		case <-time.After(sm.reconnectBackoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	sm.stop()

	time.Sleep(100 * time.Millisecond)

	if !sm.client.conn.isHealthy() {
		if err := sm.client.conn.connect(ctx); err != nil {
			sm.logger.Error("failed to reconnect connection", "error", err)
			return err
		}
	}

	sm.listenCtx, sm.cancelFunc = context.WithCancel(context.Background())

	if err := sm.initializeStreams(sm.listenCtx); err != nil {
		sm.logger.Error("failed to reinitialize streams", "error", err)
		return err
	}

	errChan := make(chan error, 2)
	go sm.listenForSVIDUpdates(sm.listenCtx, errChan)
	go sm.listenForBundleUpdates(sm.listenCtx, errChan)
	go sm.monitorErrors(sm.listenCtx, errChan)

	sm.initialized.Store(true)
	sm.streamsHealthy.Store(true)

	sm.logger.Info("successfully reconnected to SPIRE agent")
	agentID := sm.client.config.AgentID
	if agentID == "" {
		agentID = "agent"
	}
	metrics.UpdateSpireConnectionStatus(true, agentID, sm.client.podContext.Namespace, sm.client.podContext.ServiceAccount, sm.client.podContext.PodUID)

	return nil
}

func (sm *streamManager) initializeStreams(ctx context.Context) error {
	if !sm.client.conn.isHealthy() {
		if err := sm.client.conn.connect(ctx); err != nil {
			return fmt.Errorf("failed to establish connection: %w", err)
		}
	}

	client := sm.client.conn.getClient()
	if client == nil {
		return fmt.Errorf("no SPIRE client available")
	}

	streamCtx := context.Background()

	svidStream, err := client.SubscribeToX509SVIDs(streamCtx, &delegatedapi.SubscribeToX509SVIDsRequest{
		Selectors: sm.client.config.Selectors,
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to X509 SVIDs: %w", err)
	}

	trustStream, err := client.SubscribeToX509Bundles(streamCtx, &delegatedapi.SubscribeToX509BundlesRequest{})
	if err != nil {
		return fmt.Errorf("failed to subscribe to X509 bundles: %w", err)
	}

	sm.streamMutex.Lock()
	sm.svidStream = svidStream
	sm.trustStream = trustStream
	sm.streamMutex.Unlock()

	sm.logger.Debug("streams initialized successfully")
	agentID := sm.client.config.AgentID
	if agentID == "" {
		agentID = "agent"
	}
	metrics.UpdateSpireConnectionStatus(true, agentID, sm.client.podContext.Namespace, sm.client.podContext.ServiceAccount, sm.client.podContext.PodUID)

	return nil
}

func (sm *streamManager) handleStreamError(err error, streamType string, errorChan chan<- error, ctx context.Context) {
	if sm.shouldReconnect(err) {
		if err == io.EOF {
			sm.logger.Debug(streamType + " stream closed by server")
		} else if isKeepaliveError(err) {
			sm.logger.Warn(streamType+" stream keepalive error", "error", err)
		} else {
			sm.logger.Error(streamType+" stream error need reconnection", "error", err)
		}

		sm.streamsHealthy.Store(false)
		select {
		case errorChan <- err:
		case <-ctx.Done():
		}
	} else {
		sm.logger.Error("stream error not need reconnection", "error", err)
	}
}

func (sm *streamManager) listenForSVIDUpdates(ctx context.Context, errorChan chan<- error) {
	sm.logger.Debug("starting SVID update listener")
	defer sm.logger.Debug("SVID update listener stopped")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			sm.streamMutex.RLock()
			stream := sm.svidStream
			sm.streamMutex.RUnlock()

			if stream == nil {
				sm.logger.Debug("SVID stream is nil")
				return
			}

			resp, err := stream.Recv()
			if err != nil {
				sm.handleStreamError(err, "SVID", errorChan, ctx)
				return
			}

			sm.logger.Info("received X509-SVID update", "svid_count", len(resp.X509Svids))
			sm.client.svidManager.handleUpdate(resp.X509Svids, sm.client.config.SpiffeTrustDomain)
			agentID := sm.client.config.AgentID
			if agentID == "" {
				agentID = "agent"
			}
			metrics.RecordSpireSVIDReceived(agentID, "x509", sm.client.podContext.Namespace, sm.client.podContext.ServiceAccount, sm.client.podContext.PodUID)
		}
	}
}

func (sm *streamManager) listenForBundleUpdates(ctx context.Context, errorChan chan<- error) {
	sm.logger.Debug("starting bundle update listener")
	defer sm.logger.Debug("bundle update listener stopped")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			sm.streamMutex.RLock()
			stream := sm.trustStream
			sm.streamMutex.RUnlock()

			if stream == nil {
				sm.logger.Debug("trust bundle stream is nil")
				return
			}

			resp, err := stream.Recv()
			if err != nil {
				sm.logger.Error("stream error while receiving bundle update", "error", err)
				sm.handleStreamError(err, "bundle", errorChan, ctx)
				return
			}

			sm.logger.Info("received X509-Bundle update", "bundle_count", len(resp.CaCertificates))
			sm.client.bundleManager.handleUpdate(resp.CaCertificates)
			agentID := sm.client.config.AgentID
			if agentID == "" {
				agentID = "agent"
			}
			metrics.RecordSpireBundleUpdate(agentID, sm.client.podContext.Namespace, sm.client.podContext.ServiceAccount, sm.client.podContext.PodUID)
		}
	}
}

func (sm *streamManager) monitorErrors(ctx context.Context, errChan <-chan error) {
	for {
		select {
		case <-ctx.Done():
			sm.logger.Debug("error monitor stopped")
			return
		case err := <-errChan:
			if err != nil && sm.shouldReconnect(err) {
				sm.logger.Error("stream error detected, initiating reconnection", "error", err)
				go func() {
					if reconnectErr := sm.reconnect(context.Background()); reconnectErr != nil {
						sm.logger.Error("failed to reconnect after stream error", "error", reconnectErr)
					}
				}()
			}
		}
	}
}

func (sm *streamManager) shouldReconnect(err error) bool {
	sm.logger.Error("shouldReconnect", "error", err)
	if err == nil {
		return false
	}

	// Don't reconnect for context cancellation (intentional shutdown)
	if err == context.Canceled {
		return false
	}

	// Check gRPC status
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.Canceled:
			return !strings.Contains(st.Message(), "context canceled")
		case codes.Unavailable, codes.Unknown, codes.Internal, codes.PermissionDenied:
			return true
		}
	}

	errStr := err.Error()
	reconnectErrors := []string{
		"transport is closing",
		"connection refused",
		"broken pipe",
		"ENHANCE_YOUR_CALM",
		"too_many_pings",
		"keepalive ping failed",
	}

	for _, pattern := range reconnectErrors {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	// EOF means the server closed the stream
	return err == io.EOF
}
